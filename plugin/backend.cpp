#include "backend.h"
#define RESOURCE_SCANNER_LIBRARY
#include "../standalone/main.cpp"
#include <atomic>
#include <cstring>
#include <limits>

namespace vre {
namespace {
constexpr uint64_t MaxImage=256ull*1024*1024;
constexpr uint64_t MaxHeaders=1024*1024;
constexpr uint64_t Page=4096;

uint16_t read16(const Bytes& bytes,size_t offset) {
    if(offset>bytes.size() || 2>bytes.size()-offset) throw Invalid("Truncated memory image header");
    return uint16_t(bytes[offset]) | uint16_t(bytes[offset+1])<<8;
}
uint32_t read32(const Bytes& bytes,size_t offset) {
    if(offset>bytes.size() || 4>bytes.size()-offset) throw Invalid("Truncated memory image header");
    uint32_t value=0;
    for(unsigned i=0;i<4;i++) value|=uint32_t(bytes[offset+i])<<(i*8);
    return value;
}
void write32(Bytes& bytes,size_t offset,uint32_t value) {
    if(offset>bytes.size() || 4>bytes.size()-offset) throw Invalid("Truncated memory image header");
    for(unsigned i=0;i<4;i++) bytes[offset+i]=uint8_t(value>>(i*8));
}
void check_state(const IsValid& valid,const ScanDeadline& deadline) {
    deadline.check(true);
    if(!valid()) throw Invalid("Debugger state changed during capture. Pause the target and scan again");
}
void read_range(const Module& selected,const ReadMemory& read,const IsValid& valid,
                const ScanDeadline& deadline,uint64_t rva,void* destination,size_t size) {
    if(rva>selected.size || uint64_t(size)>selected.size-rva) throw Invalid("Memory read exceeds the selected module");
    auto output=static_cast<uint8_t*>(destination);
    size_t done=0;
    while(done<size) {
        check_state(valid,deadline);
        const uint64_t current=selected.base+rva+done;
        const size_t count=std::min(size-done,size_t(Page-(current&(Page-1))));
        if(!read(current,output+done,count)) {
            throw Invalid("Cannot read module memory at "+hex(current)+
                ". An image section may be inaccessible or discarded; no incomplete snapshot was accepted");
        }
        done+=count;
    }
}

fs::path create_staging(const fs::path& output) {
    static std::atomic<uint64_t> sequence{0};
    for(unsigned attempt=0;attempt<32;attempt++) {
        fs::path stage=output;
        stage+=L".partial-vre-"+std::to_wstring(GetCurrentProcessId())+L"-"+
               std::to_wstring(GetTickCount64())+L"-"+std::to_wstring(sequence.fetch_add(1));
        if(fs::create_directory(stage)) return stage;
    }
    throw Invalid("Cannot reserve a temporary output directory");
}
void cleanup_staging(const fs::path& stage,const fs::path& parent) noexcept {
    // The stage was created by this operation, as a direct sibling of output.
    // remove_all removes reparse-point links themselves rather than their target.
    try {
        if(fs::weakly_canonical(stage.parent_path())!=fs::weakly_canonical(parent)) return;
        std::error_code error;
        fs::remove_all(stage,error);
    } catch(...) {}
}
}

class Snapshot {
public:
    Module selected;
    std::unique_ptr<PE> image;
    std::vector<Table> tables;
    std::vector<Candidate> summaries;
};

SnapshotPtr capture(const Module& selected,const ReadMemory& read,const IsValid& valid) {
    if(!read || !valid) throw Invalid("Memory reader and debugger state validator are required");
    if(!selected.base || selected.size<64 || selected.size>MaxImage ||
       selected.size-1>std::numeric_limits<uint64_t>::max()-selected.base)
        throw Invalid("Selected module has an invalid range or exceeds the 256 MiB image limit");
    const ScanDeadline deadline(20000);
    check_state(valid,deadline);

    Bytes dos(64);
    read_range(selected,read,valid,deadline,0,dos.data(),dos.size());
    if(read16(dos,0)!=IMAGE_DOS_SIGNATURE) throw Invalid("Selected module has no readable DOS/PE headers");
    const uint64_t nt=read32(dos,0x3c);
    if(nt>MaxHeaders || nt>selected.size || 24>selected.size-nt) throw Invalid("Invalid PE header offset");
    Bytes prefix(size_t(nt+24));
    read_range(selected,read,valid,deadline,0,prefix.data(),prefix.size());
    if(prefix.size()<dos.size() || !std::equal(dos.begin(),dos.end(),prefix.begin()))
        throw Invalid("Module headers changed during capture; scan again while paused");
    if(read32(prefix,size_t(nt))!=IMAGE_NT_SIGNATURE) throw Invalid("Invalid PE signature in target memory");
    if(read16(prefix,size_t(nt+4))!=IMAGE_FILE_MACHINE_AMD64) throw Invalid("This plugin supports x64 modules only");
    const uint32_t count=read16(prefix,size_t(nt+6));
    const uint32_t optSize=read16(prefix,size_t(nt+20));
    if(!count || count>96 || optSize<112 || optSize>4096) throw Invalid("Invalid PE optional header or section count");
    const uint64_t optional=nt+24, sectionTable=optional+optSize;
    const uint64_t minimumHeaders=sectionTable+uint64_t(count)*40;
    if(minimumHeaders>selected.size || minimumHeaders>MaxHeaders) throw Invalid("PE section headers exceed the module");
    Bytes headers(static_cast<size_t>(minimumHeaders));
    read_range(selected,read,valid,deadline,0,headers.data(),headers.size());
    if(!std::equal(prefix.begin(),prefix.end(),headers.begin()))
        throw Invalid("Module headers changed during capture; scan again while paused");
    if(read16(headers,size_t(optional))!=IMAGE_NT_OPTIONAL_HDR64_MAGIC) throw Invalid("This plugin requires PE32+ headers");
    const uint32_t imageSize=read32(headers,size_t(optional+56));
    const uint32_t headerSize=read32(headers,size_t(optional+60));
    if(!imageSize || imageSize>selected.size || imageSize>MaxImage ||
       headerSize<minimumHeaders || headerSize>imageSize || headerSize>MaxHeaders)
        throw Invalid("Invalid SizeOfImage or SizeOfHeaders in target memory");
    Bytes completeHeaders(headerSize);
    read_range(selected,read,valid,deadline,0,completeHeaders.data(),completeHeaders.size());
    if(!std::equal(headers.begin(),headers.end(),completeHeaders.begin()))
        throw Invalid("Module headers changed during capture; scan again while paused");
    headers=std::move(completeHeaders);

    struct Span {uint32_t rva,size;size_t header;};
    std::vector<Span> spans;
    for(uint32_t i=0;i<count;i++) {
        const size_t offset=size_t(sectionTable)+size_t(i)*40;
        const uint32_t rva=read32(headers,offset+12);
        const uint32_t length=std::max(read32(headers,offset+8),read32(headers,offset+16));
        if(!length) continue;
        if(rva<headerSize || rva>imageSize || length>imageSize-rva) throw Invalid("Section range exceeds the mapped image");
        for(const auto& span:spans)
            if(uint64_t(rva)<uint64_t(span.rva)+span.size && uint64_t(span.rva)<uint64_t(rva)+length)
                throw Invalid("Overlapping virtual sections in target memory");
        spans.push_back({rva,length,offset});
    }
    if(spans.empty()) throw Invalid("Selected module has no mapped sections");
    Bytes bytes(imageSize,0);
    std::copy(headers.begin(),headers.end(),bytes.begin());
    for(const auto& span:spans) {
        read_range(selected,read,valid,deadline,span.rva,bytes.data()+span.rva,span.size);
        // Normalize the captured image for the same parser used by standalone.
        write32(bytes,span.header+16,span.size);
        write32(bytes,span.header+20,span.rva);
    }
    Bytes after(headers.size());
    read_range(selected,read,valid,deadline,0,after.data(),after.size());
    if(after!=headers) throw Invalid("Module headers changed during capture; scan again while paused");
    check_state(valid,deadline);
    auto snapshot=std::make_shared<Snapshot>();
    snapshot->selected=selected;
    snapshot->selected.size=imageSize;
    snapshot->image=std::make_unique<PE>(std::move(bytes));
    snapshot->tables=detect(*snapshot->image,&deadline);
    check_state(valid,deadline);
    for(const auto& table:snapshot->tables)
        snapshot->summaries.push_back({table.rva,table.key,table.resources.size(),table.total});
    return snapshot;
}

const Module& module(const SnapshotPtr& snapshot) {
    if(!snapshot) throw Invalid("No memory snapshot is selected");
    return snapshot->selected;
}
const std::vector<Candidate>& candidates(const SnapshotPtr& snapshot) {
    if(!snapshot) throw Invalid("No memory snapshot is selected");
    return snapshot->summaries;
}

ExtractResult extract_snapshot(const SnapshotPtr& snapshot,size_t candidateIndex,const fs::path& output) {
    if(!snapshot || candidateIndex>=snapshot->tables.size()) throw Invalid("Select a resource table from a completed scan");
    const fs::path destination=fs::absolute(output).lexically_normal();
    if(destination.filename().empty() || !fs::is_directory(destination.parent_path()))
        throw Invalid("Choose a new output folder beneath an existing directory");
    if(fs::exists(destination)) throw Invalid("Output folder already exists; choose a new folder");
    const fs::path stage=create_staging(destination), content=stage/L"resources";
    const auto& table=snapshot->tables[candidateIndex];
    try {
        fs::path input=snapshot->selected.path.empty()?snapshot->selected.name:snapshot->selected.path;
        if(input.empty()) input=L"module";
        ::extract(*snapshot->image,table,input,content);
        const auto manifestPath=content/L"manifest.json";
        std::ifstream source(manifestPath,std::ios::binary);
        std::string manifest((std::istreambuf_iterator<char>(source)),{});
        if(!source || manifest.size()<2 || manifest[0]!='{') throw Invalid("Cannot read staged resource manifest");
        source.close();
        const std::string origin="\n  \"method\": \"x64dbg-memory\",\n  \"module_base\": "+quote(hex(snapshot->selected.base))+
            ",\n  \"capture\": \"copied while paused; structural validation, payload initialization is not proven\",";
        manifest.insert(1,origin);
        writeFile(manifestPath,manifest.data(),manifest.size());
        // MoveFileW never replaces even an empty destination created meanwhile.
        if(!MoveFileW(content.c_str(),destination.c_str()))
            throw Invalid("Cannot publish resource output (Windows error "+std::to_string(GetLastError())+
                          "). The destination may already exist");
        cleanup_staging(stage,destination.parent_path());
        return {destination,table.resources.size(),table.total};
    } catch(...) {
        cleanup_staging(stage,destination.parent_path());
        throw;
    }
}
}
