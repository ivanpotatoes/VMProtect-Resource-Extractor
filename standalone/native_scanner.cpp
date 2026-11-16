// The CLI and DLL deliberately share the parser and all structural limits.
#define RESOURCE_SCANNER_LIBRARY
#include "main.cpp"
#include <cstdlib>
#include <cstring>

// ABI v1, cdecl. Input is a complete file-layout PE buffer, not a host pointer
// to guest memory. Callers must provide a readable buffer of input_size bytes.
// Every non-null response is malloc-owned and must be released with
// resource_scanner_free, including error responses. Size excludes trailing NUL.
// Status: 0 success; 1 no candidate; 2 invalid input; 3 allocation failure;
//         4 internal error; 5 time limit. A valid hint selects that revalidated table;
// an invalid hint falls back to complete detection.
// Scans have a 20-second limit. The additive scan_timed entry point accepts a
// shorter timeout in milliseconds (0 fails immediately), capped at 20 seconds.
namespace {
int reply(int status,const std::string& json,char** output,size_t* output_size) {
    char* result=static_cast<char*>(std::malloc(json.size()+1));
    if(!result) return 3;
    std::memcpy(result,json.data(),json.size()); result[json.size()]='\0';
    *output=result; *output_size=json.size(); return status;
}
std::string metadata(const std::vector<Table>& tables,bool hinted,const ScanDeadline& deadline) {
    std::ostringstream out;
    out<<"{\"abi\":1,\"hint_used\":"<<(hinted?"true":"false")<<",\"candidates\":[";
    for(size_t i=0;i<tables.size();i++) {
        const auto& table=tables[i];
        if(i) out<<',';
        out<<"{\"table_rva\":"<<table.rva<<",\"key\":"<<table.key
           <<",\"total\":"<<table.total<<",\"resources\":[";
        for(size_t j=0;j<table.resources.size();j++) {
            deadline.check();
            const auto& resource=table.resources[j];
            if(j) out<<',';
            out<<"{\"type\":"<<resource.ids[0].json()<<",\"name\":"<<resource.ids[1].json()
               <<",\"language\":"<<resource.ids[2].json()<<",\"data_rva\":"<<resource.rva
               <<",\"size\":"<<resource.size<<",\"codepage\":"<<resource.codepage<<'}';
        }
        out<<"]}";
    }
    out<<"]}"; return out.str();
}
}

extern "C" __declspec(dllexport) unsigned __cdecl resource_scanner_abi() noexcept { return 1; }

extern "C" __declspec(dllexport) void __cdecl resource_scanner_free(void* response) noexcept {
    std::free(response);
}

extern "C" __declspec(dllexport) int __cdecl resource_scanner_scan_timed(
    const uint8_t* input,size_t input_size,int use_hint,uint32_t table_rva,
    uint32_t key,uint32_t timeout_ms,char** output,size_t* output_size) noexcept {
    if(!output||!output_size) return 2;
    *output=nullptr; *output_size=0;
    try {
        if(!input||input_size<64||input_size>MAX_FILE) throw Invalid("Input size must be 64 bytes to 1 GiB");
        ScanDeadline deadline(std::min(timeout_ms,20000u));
        deadline.check(true);
        PE pe(Bytes(input,input+input_size));
        deadline.check(true);
        std::vector<Table> tables;
        bool hinted=false;
        if(use_hint) {
            try { tables.push_back(Parser(pe,table_rva,key,&deadline).parse()); hinted=true; }
            catch(const Invalid&) { /* Stale hint: discover again with full validation. */ }
        }
        if(tables.empty()) tables=detect(pe,&deadline);
        const int status=tables.empty()?1:0;
        auto json=metadata(tables,hinted,deadline);
        deadline.check(true);
        return reply(status,json,output,output_size);
    } catch(const std::bad_alloc&) {
        return 3;
    } catch(const ScanTimedOut& error) {
        try { return reply(5,"{\"abi\":1,\"error\":"+quote(error.what())+"}",output,output_size); }
        catch(...) { return 3; }
    } catch(const Invalid& error) {
        try { return reply(2,"{\"abi\":1,\"error\":"+quote(error.what())+"}",output,output_size); }
        catch(...) { return 3; }
    } catch(const std::exception& error) {
        try { return reply(4,"{\"abi\":1,\"error\":"+quote(error.what())+"}",output,output_size); }
        catch(...) { return 3; }
    } catch(...) {
        return 4;
    }
}

extern "C" __declspec(dllexport) int __cdecl resource_scanner_scan(
    const uint8_t* input,size_t input_size,int use_hint,uint32_t table_rva,
    uint32_t key,char** output,size_t* output_size) noexcept {
    return resource_scanner_scan_timed(input,input_size,use_hint,table_rva,key,20000,output,output_size);
}
