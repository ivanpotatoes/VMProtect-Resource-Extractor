#define NOMINMAX
#include <windows.h>
#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace fs = std::filesystem;
using Bytes = std::vector<uint8_t>;
constexpr uint32_t MAX_ENTRIES = 4096, MAX_RESOURCES = 16384;
constexpr uint64_t MAX_FILE = 1024ull*1024*1024, MAX_TOTAL = 512ull*1024*1024;
struct Invalid : std::runtime_error { using runtime_error::runtime_error; };
struct ScanTimedOut : std::runtime_error { ScanTimedOut():std::runtime_error("Resource scan exceeded time limit") {} };
struct ScanDeadline {
    std::chrono::steady_clock::time_point expires;
    mutable uint32_t checks=0;
    explicit ScanDeadline(uint32_t milliseconds):expires(std::chrono::steady_clock::now()+std::chrono::milliseconds(milliseconds)) {}
    void check(bool immediate=false) const {
        // Amortize clock reads while still checking both candidate loops and trees.
        if((immediate || (++checks&1023u)==0) && std::chrono::steady_clock::now()>=expires) throw ScanTimedOut();
    }
};
uint32_t rol(uint32_t x, unsigned n) { n &= 31; return (x << n) | (x >> ((32-n)&31)); }
std::string utf8(const std::wstring& s) {
    if(s.empty()) return {};
    int n=WideCharToMultiByte(CP_UTF8,WC_ERR_INVALID_CHARS,s.data(),int(s.size()),nullptr,0,nullptr,nullptr);
    if(!n) throw Invalid("Invalid UTF-16 resource name");
    std::string r(n,'\0'); WideCharToMultiByte(CP_UTF8,WC_ERR_INVALID_CHARS,s.data(),int(s.size()),r.data(),n,nullptr,nullptr); return r;
}
std::string hex(uint64_t n) { std::ostringstream s; s<<"0x"<<std::hex<<n; return s.str(); }
std::string quote(const std::string& s) {
    std::ostringstream o; o<<'"'; const char* h="0123456789abcdef";
    for(unsigned char c:s) { if(c=='"'||c=='\\') o<<'\\'<<c; else if(c<32) o<<"\\u00"<<h[c>>4]<<h[c&15]; else o<<c; } o<<'"'; return o.str();
}
struct Section { uint32_t va, raw, size; };
struct PE {
    Bytes b; std::vector<Section> sections; uint32_t headers=0; bool x64=false;
    void bounds(uint64_t p,uint64_t n) const { if(p>b.size()||n>b.size()-p) throw Invalid("Truncated PE or out-of-file range"); }
    uint16_t u16(uint64_t p) const { bounds(p,2); return b[size_t(p)] | uint16_t(b[size_t(p)+1])<<8; }
    uint32_t u32(uint64_t p) const { bounds(p,4); uint32_t v=0; for(int i=0;i<4;i++) v|=uint32_t(b[size_t(p)+i])<<(8*i); return v; }
    explicit PE(const fs::path& p) {
        auto len=fs::file_size(p); if(len<64||len>MAX_FILE) throw Invalid("Input size must be 64 bytes to 1 GiB");
        b.resize(size_t(len)); std::ifstream f(p,std::ios::binary); if(!f.read(reinterpret_cast<char*>(b.data()),std::streamsize(len))) throw Invalid("Cannot read input file");
        parse();
    }
    explicit PE(Bytes data):b(std::move(data)) { parse(); }
    void parse() {
        if(b.size()<64||b.size()>MAX_FILE) throw Invalid("Input size must be 64 bytes to 1 GiB");
        if(u16(0)!=0x5a4d) throw Invalid("Not a DOS/PE image");
        uint64_t nt=u32(0x3c); if(u32(nt)!=0x4550) throw Invalid("Invalid PE signature");
        unsigned count=u16(nt+6), optsize=u16(nt+20); uint64_t opt=nt+24;
        if(!count||count>96||optsize<64) throw Invalid("Invalid section count or optional header");
        bounds(opt,optsize); auto magic=u16(opt); if(magic!=0x10b&&magic!=0x20b) throw Invalid("Unsupported PE optional header"); x64=magic==0x20b;
        headers=u32(opt+60); bounds(0,headers);
        uint64_t table=opt+optsize; bounds(table,uint64_t(count)*40);
        for(unsigned i=0;i<count;i++) {
            uint64_t q=table+i*40; Section s{u32(q+12),u32(q+20),u32(q+16)};
            if(!s.size) continue; bounds(s.raw,s.size);
            if(s.va<headers||s.raw<headers||uint64_t(s.va)+s.size>0x100000000ull) throw Invalid("Invalid section range");
            for(auto t:sections) if((uint64_t(s.va)<uint64_t(t.va)+t.size&&uint64_t(t.va)<uint64_t(s.va)+s.size) || (uint64_t(s.raw)<uint64_t(t.raw)+t.size&&uint64_t(t.raw)<uint64_t(s.raw)+s.size)) throw Invalid("Overlapping PE sections");
            sections.push_back(s);
        }
    }
    size_t map(uint64_t rva,uint64_t n) const {
        if(rva<headers&&n<=uint64_t(headers)-rva) { bounds(rva,n); return size_t(rva); }
        for(auto s:sections) if(rva>=s.va&&rva- s.va<s.size&&n<=uint64_t(s.size)-(rva-s.va)) return size_t(s.raw+(rva-s.va));
        throw Invalid("RVA is not fully backed by file data");
    }
};
struct ID { bool named=false; uint32_t number=0; std::string name;
    std::string json() const { return named?quote(name):std::to_string(number); }
};
struct Resource { std::array<ID,3> ids; uint32_t rva,size,codepage; size_t fileOffset; };
struct Table { uint32_t rva,key; std::vector<Resource> resources; uint64_t total=0; };
class Parser {
    const PE& pe; Table result; uint64_t tableEnd; std::set<uint32_t> dirs; std::set<std::string> paths;
    const ScanDeadline* deadline;
    uint32_t word(uint64_t offset) const {
        if(offset>tableEnd-result.rva || 4>tableEnd-result.rva-offset) throw Invalid("Table field outside its section");
        return pe.u32(pe.map(uint64_t(result.rva)+offset,4))^result.key;
    }
    ID id(uint32_t v) const {
        if(!(v&0x80000000)) { if(v>65535) throw Invalid("Resource ID out of range"); return {false,v,{}}; }
        uint64_t off=v&0x7fffffff; std::wstring s;
        for(unsigned j=0;j<4096;j++) {
            if(deadline) deadline->check();
            uint64_t rva=uint64_t(result.rva)+off+j*2;
            if(rva>=tableEnd||2>tableEnd-rva) throw Invalid("Name outside table section");
            uint16_t c=pe.u16(pe.map(rva,2))^uint16_t(rol(result.key,j)+j);
            if(!c) { if(s.empty()) throw Invalid("Empty resource name"); return {true,0,utf8(s)}; }
            s.push_back(wchar_t(c));
        }
        throw Invalid("Resource name exceeds 4095 UTF-16 units");
    }
    void walk(uint32_t offset,unsigned depth,std::array<ID,3> ids) {
        if(deadline) deadline->check();
        if(depth>2||!dirs.insert(offset).second||dirs.size()>MAX_RESOURCES) throw Invalid("Cyclic, shared or too deep resource directory");
        uint32_t named=word(offset), numeric=word(uint64_t(offset)+4);
        if(named>MAX_ENTRIES||numeric>MAX_ENTRIES||uint64_t(named)+numeric==0||uint64_t(named)+numeric>MAX_ENTRIES) throw Invalid("Invalid directory counts");
        std::set<std::string> identifiers;
        for(uint32_t i=0;i<named+numeric;i++) {
            if(deadline) deadline->check();
            uint64_t p=uint64_t(offset)+8+uint64_t(i)*8; uint32_t ident=word(p), target=word(p+4);
            if(bool(ident&0x80000000)!=(i<named)) throw Invalid("Named/integer entry ordering mismatch");
            ids[depth]=id(ident); if(!identifiers.insert(ids[depth].json()).second) throw Invalid("Duplicate identifier");
            if(depth<2) {
                if(!(target&0x80000000)) throw Invalid("Expected child directory");
                walk(target&0x7fffffff,depth+1,ids);
            } else {
                if((target&0x80000000)||ids[2].named) throw Invalid("Invalid language leaf");
                uint32_t rva=word(target), size=word(uint64_t(target)+4), cp=word(uint64_t(target)+8), reserved=word(uint64_t(target)+12);
                if(reserved||cp>65535||size>256u*1024*1024||result.resources.size()>=MAX_RESOURCES||result.total+size>MAX_TOTAL) throw Invalid("Invalid or oversized resource leaf");
                size_t fileOffset=pe.map(rva,size);
                std::string path=ids[0].json()+"/"+ids[1].json()+"/"+ids[2].json();
                if(!paths.insert(path).second) throw Invalid("Duplicate resource path");
                result.resources.push_back({ids,rva,size,cp,fileOffset}); result.total+=size;
            }
        }
    }
public:
    Parser(const PE& p,uint32_t rva,uint32_t key,const ScanDeadline* limit=nullptr):pe(p),result{rva,key,{},0},tableEnd(0),deadline(limit) {
        for(auto s:p.sections) if(rva>=s.va&&uint64_t(rva)-s.va<s.size) tableEnd=uint64_t(s.va)+s.size;
        if(!tableEnd) throw Invalid("Table is not in a file-backed section");
    }
    Table parse() { if(deadline) deadline->check(true); walk(0,0,{}); if(result.resources.empty()) throw Invalid("Empty resource tree"); return result; }
};

std::vector<Table> detect(const PE& pe,const ScanDeadline* deadline=nullptr) {
    if(deadline) deadline->check(true);
    std::vector<Table> found; uint64_t attempts=0;
    for(auto s:pe.sections) {
        if(s.size<24) continue;
        for(uint64_t pos=s.raw;pos+24<=uint64_t(s.raw)+s.size;pos++) {
            if(deadline) deadline->check();
            uint32_t a=pe.u32(pos), b=pe.u32(pos+4), diff=a^b;
            if(diff>8191) continue;
            // XOR cancels the key. Root counts bound the unknown low key bits.
            uint32_t ident=pe.u32(pos+8)^a, target=pe.u32(pos+12)^a;
            if(!(target&0x80000000)) continue;
            uint32_t off=target&0x7fffffff;
            uint64_t available=uint64_t(s.raw)+s.size-pos;
            if((off&~8191u)>=available) continue;
            uint32_t rva=s.va+uint32_t(pos-s.raw);
            for(uint32_t named=0;named<=MAX_ENTRIES;named++) {
                if(deadline) deadline->check();
                uint32_t numeric=diff^named;
                if(numeric>MAX_ENTRIES||named+numeric==0||named+numeric>MAX_ENTRIES) continue;
                if(bool(ident&0x80000000)!=(named!=0)) continue;
                if(!named && (ident^named)>65535) continue;
                uint32_t child=off^named;
                if(child<8+8*(named+numeric)||uint64_t(child)+8>available) continue;
                uint32_t key=a^named;
                uint32_t ca=pe.u32(pos+child)^key, cb=pe.u32(pos+child+4)^key;
                if(ca>MAX_ENTRIES||cb>MAX_ENTRIES||uint64_t(ca)+cb==0||uint64_t(ca)+cb>MAX_ENTRIES) continue;
                if(++attempts>1000000) throw Invalid("Too many candidate trees; supply --table-rva and --key");
                try {
                    auto table=Parser(pe,rva,key,deadline).parse(); found.push_back(std::move(table));
                    if(found.size()>64) throw std::runtime_error("Too many valid tables; use explicit --table-rva and --key");
                } catch(const Invalid&) {}
            }
        }
    }
    if(deadline) deadline->check(true);
    return found;
}

void writeFile(const fs::path& path,const char* bytes,size_t n) {
    std::ofstream f(path,std::ios::binary); if(!f) throw std::runtime_error("Cannot create output file");
    f.write(bytes,std::streamsize(n)); f.close(); if(!f) throw std::runtime_error("Output write failed");
}
void extract(const PE& pe,const Table& t,const fs::path& input,const fs::path& output) {
    if(fs::exists(output)) throw Invalid("Output directory already exists; choose a new --output directory");
    if(!fs::is_directory(output.parent_path())) throw Invalid("Output parent directory does not exist");
    fs::path staging=output; staging+=L".partial-"+std::to_wstring(GetCurrentProcessId());
    if(!fs::create_directory(staging)) throw Invalid("Temporary output directory already exists");
    try {
        std::ostringstream manifest;
        manifest<<"{\n  \"format\": \"vmprotect-resource-extractor-1\",\n  \"input\": "<<quote(utf8(input.filename().wstring()))
          <<",\n  \"architecture\": "<<quote(pe.x64?"x64":"x32")<<",\n  \"table_rva\": "<<quote(hex(t.rva))<<",\n  \"key\": "<<quote(hex(t.key))
          <<",\n  \"validation\": \"structural; plaintext is not authenticated\",\n  \"resources\": [\n";
        for(size_t index=0;index<t.resources.size();index++) {
            const auto& r=t.resources[index]; Bytes plain(r.size);
            for(uint32_t i=0;i<r.size;i++) plain[i]=pe.b[r.fileOffset+i]^uint8_t(rol(t.key,i)+i);
            char filename[64]; snprintf(filename,sizeof(filename),"resource-%04zu.bin",index+1);
            writeFile(staging/filename,reinterpret_cast<const char*>(plain.data()),plain.size());
            manifest<<"    {\"type\": "<<r.ids[0].json()<<", \"name\": "<<r.ids[1].json()<<", \"language\": "<<r.ids[2].json()<<", \"codepage\": "<<r.codepage<<", \"data_rva\": "<<quote(hex(r.rva))<<", \"size\": "<<r.size<<", \"file\": "<<quote(filename)<<"}"<<(index+1<t.resources.size()?",":"")<<"\n";
        }
        manifest<<"  ]\n}\n"; auto m=manifest.str(); writeFile(staging/L"manifest.json",m.data(),m.size());
        fs::rename(staging,output);
    } catch(...) { std::error_code ec; fs::remove_all(staging,ec); throw; }
}
uint32_t number(const std::wstring& s) {
    size_t end=0; if(s.empty()||s[0]==L'-') throw Invalid("Invalid numeric argument");
    auto n=std::stoull(s,&end,0); if(end!=s.size()||n>0xffffffffull) throw Invalid("Numeric argument outside DWORD range"); return uint32_t(n);
}
void help() {
    std::cout<<"VMProtect Resource Extractor - standalone\n\n"
      "Usage: vmp-resource-extractor.exe input.exe [--output directory] [--list]\n"
      "       vmp-resource-extractor.exe input.dll --table-rva 0x... --key 0x...\n\n"
      "Reads the PE file without executing it. Extracts the private resource tree\n"
      "to numbered binary files plus manifest.json (type, name, language, codepage).\n"
      "The original file is never patched. An existing output folder is not replaced.\n"
      "--list lists structurally valid candidate tables without extracting.\n"
      "Default output: <input filename>.resources next to the input.\n"
      "Use 0x prefixes for hexadecimal arguments.\n";
}
#ifndef RESOURCE_SCANNER_LIBRARY
int wmain(int argc,wchar_t** argv) {
    try {
        if(argc<2) { help(); return 0; }
        fs::path input,output; bool list=false,hasRva=false,hasKey=false; uint32_t rva=0,key=0;
        for(int i=1;i<argc;i++) {
            std::wstring a=argv[i];
            auto next=[&](){ if(i+1>=argc) throw Invalid("Missing option value"); return std::wstring(argv[++i]); };
            if(a==L"--help"||a==L"-h") {help();return 0;}
            else if(a==L"--output"||a==L"-o") output=next();
            else if(a==L"--list") list=true;
            else if(a==L"--table-rva") {rva=number(next());hasRva=true;}
            else if(a==L"--key") {key=number(next());hasKey=true;}
            else if(!a.empty()&&a[0]==L'-') throw Invalid("Unknown option");
            else if(input.empty()) input=a; else throw Invalid("Specify one input file");
        }
        if(input.empty()||hasRva!=hasKey) throw Invalid("Specify an input and supply both --table-rva and --key, or neither");
        input=fs::absolute(input); PE pe(input);
        std::vector<Table> tables;
        if(hasRva) tables.push_back(Parser(pe,rva,key).parse()); else tables=detect(pe);
        if(tables.empty()) throw Invalid("No supported private resource tree found. The file may be unpacked, unsupported, damaged or require runtime unpacking");
        for(const auto& t:tables) std::cout<<"table="<<hex(t.rva)<<" key="<<hex(t.key)<<" resources="<<t.resources.size()<<" bytes="<<t.total<<"\n";
        if(list) return 0;
        if(tables.size()!=1) throw Invalid("Multiple valid tables found; select one using --table-rva and --key");
        if(output.empty()) { output=input; output+=L".resources"; } else output=fs::absolute(output);
        extract(pe,tables[0],input,output);
        std::cout<<"Extracted "<<tables[0].resources.size()<<" resources.\nOutput: "<<utf8(output.wstring())<<"\n";
        return 0;
    } catch(const std::exception& e) {std::cerr<<"error: "<<e.what()<<"\n";return 1;}
}
#endif
