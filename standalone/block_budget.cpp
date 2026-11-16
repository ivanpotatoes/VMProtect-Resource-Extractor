// Optional synchronous Unicorn scheduler. Never changes guest registers/memory.
#define NOMINMAX
#include <windows.h>
#include <capstone/capstone.h>
#include <algorithm>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <memory>
#include <unordered_map>
#include <vector>

#define API extern "C" __declspec(dllexport)
using ReadFn=int(*)(void*,uint64_t,void*,size_t);
using StopFn=int(*)(void*);
enum Reason : uint32_t { RUNNING=0, SLICE=1, TOTAL=2, DEADLINE=3, BAD_BLOCK=4, READ_ERROR=5, DECODE_ERROR=6, HOST_ERROR=7 };
struct Key {uint64_t address; uint32_t size; bool operator==(const Key& k) const {return address==k.address&&size==k.size;}};
struct Hash {size_t operator()(const Key& k) const {return size_t(k.address^(uint64_t(k.size)<<48));}};
struct Entry {std::vector<uint8_t> bytes; uint32_t instructions;};
struct Budget {
    HMODULE dll=nullptr;
    decltype(&cs_open) open=nullptr; decltype(&cs_close) close=nullptr;
    decltype(&cs_version) version=nullptr;
    decltype(&cs_malloc) allocate=nullptr; decltype(&cs_free) free=nullptr;
    decltype(&cs_disasm_iter) decode=nullptr;
    csh handle=0; cs_insn* instruction=nullptr;
    ReadFn read=nullptr; StopFn stop=nullptr;
    const uint8_t* image=nullptr; uint64_t image_base=0,image_size=0;
    uint64_t total_limit=0,total=0,slice_limit=0,slice=0,blocks=0,decodes=0,hits=0;
    LONGLONG deadline=0,frequency=0;
    uint32_t reason=RUNNING;
    size_t bytes=0;
    std::unordered_map<Key,Entry,Hash> cache;
    ~Budget(){if(instruction&&free)free(instruction,1); if(handle&&close)close(&handle); if(dll)FreeLibrary(dll);}
    void halt(void* uc,Reason r){reason=r;stop(uc);}
};
template<class T> T symbol(HMODULE dll,const char* name){return reinterpret_cast<T>(GetProcAddress(dll,name));}

API void* bb_create(const wchar_t* capstone,void* read,void* stop,uint64_t limit) noexcept {
    if(!capstone||!read||!stop||!limit)return nullptr;
    try {
        auto p=std::make_unique<Budget>();
        if(!std::filesystem::path(capstone).is_absolute())return nullptr;
        p->dll=LoadLibraryExW(capstone,nullptr,LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR|LOAD_LIBRARY_SEARCH_DEFAULT_DIRS);
        if(!p->dll)return nullptr;
        p->version=symbol<decltype(p->version)>(p->dll,"cs_version");
        if(!p->version)return nullptr;
        int major=0,minor=0;p->version(&major,&minor);
        if(major!=CS_API_MAJOR)return nullptr;
        p->open=symbol<decltype(p->open)>(p->dll,"cs_open");
        p->close=symbol<decltype(p->close)>(p->dll,"cs_close");
        p->allocate=symbol<decltype(p->allocate)>(p->dll,"cs_malloc");
        p->free=symbol<decltype(p->free)>(p->dll,"cs_free");
        p->decode=symbol<decltype(p->decode)>(p->dll,"cs_disasm_iter");
        if(!p->open||!p->close||!p->allocate||!p->free||!p->decode)return nullptr;
        if(p->open(CS_ARCH_X86,CS_MODE_64,&p->handle)!=CS_ERR_OK)return nullptr;
        p->instruction=p->allocate(p->handle); if(!p->instruction)return nullptr;
        p->read=reinterpret_cast<ReadFn>(read); p->stop=reinterpret_cast<StopFn>(stop); p->total_limit=limit;
        LARGE_INTEGER f; QueryPerformanceFrequency(&f); p->frequency=f.QuadPart;
        return p.release();
    }catch(...){return nullptr;}
}
API void bb_destroy(void* state) noexcept {delete static_cast<Budget*>(state);}
API int bb_set_image(void* state,uint64_t base,uint64_t size,void* pointer) noexcept {
    auto p=static_cast<Budget*>(state); if(!p)return 0;
    // Borrowed storage must remain the backing of the same Unicorn mapping until
    // cleared or destroyed. Configure only while emulation is stopped.
    if(!pointer&&!base&&!size){p->image=nullptr;p->image_base=0;p->image_size=0;return 1;}
    const auto host=reinterpret_cast<uintptr_t>(pointer);
    if(!pointer||!size||size>SIZE_MAX||size-1>UINT64_MAX-base||size-1>UINTPTR_MAX-host)return 0;
    p->image=static_cast<const uint8_t*>(pointer);p->image_base=base;p->image_size=size;return 1;
}
API int bb_begin(void* state,uint64_t slice,uint32_t milliseconds) noexcept {
    auto p=static_cast<Budget*>(state); if(!p||!slice||!milliseconds)return 0;
    LARGE_INTEGER now; QueryPerformanceCounter(&now);
    p->deadline=now.QuadPart+(p->frequency*milliseconds)/1000;
    p->slice_limit=slice;p->slice=0;p->reason=RUNNING;return 1;
}
API uint32_t bb_reason(void* state) noexcept {return state?static_cast<Budget*>(state)->reason:HOST_ERROR;}
API uint64_t bb_total(void* state) noexcept {return state?static_cast<Budget*>(state)->total:0;}
API uint64_t bb_slice(void* state) noexcept {return state?static_cast<Budget*>(state)->slice:0;}
API uint64_t bb_blocks(void* state) noexcept {return state?static_cast<Budget*>(state)->blocks:0;}
API uint64_t bb_decodes(void* state) noexcept {return state?static_cast<Budget*>(state)->decodes:0;}
API uint64_t bb_hits(void* state) noexcept {return state?static_cast<Budget*>(state)->hits:0;}

API void bb_callback(void* uc,uint64_t address,uint32_t size,void* state) noexcept {
    auto p=static_cast<Budget*>(state); if(!p)return;
    try {
        if(p->reason!=RUNNING){p->stop(uc);return;}
        // A terminal budget condition is checked before reading/decoding a block.
        if(p->total>=p->total_limit){p->halt(uc,TOTAL);return;}
        if(p->slice>=p->slice_limit){p->halt(uc,SLICE);return;}
        // Synchronous coarse checks avoid a host clock query on every hot block.
        // The caller retains an absolute Unicorn timeout as emergency protection.
        if(!p->slice || !(p->blocks&255)) {
            LARGE_INTEGER now; QueryPerformanceCounter(&now);
            if(now.QuadPart>=p->deadline){p->halt(uc,DEADLINE);return;}
        }
        if(!size||size>16384){p->halt(uc,BAD_BLOCK);return;}
        uint8_t bytes[16384];
        if(p->image&&address>=p->image_base&&address-p->image_base<p->image_size&&
           size<=p->image_size-(address-p->image_base)) {
            std::memcpy(bytes,p->image+static_cast<size_t>(address-p->image_base),size);
        }else if(p->read(uc,address,bytes,size)){p->halt(uc,READ_ERROR);return;}
        Key key{address,size}; uint32_t count=0;
        auto hit=p->cache.find(key);
        if(hit!=p->cache.end()&&std::memcmp(hit->second.bytes.data(),bytes,size)==0){count=hit->second.instructions;++p->hits;}
        else {
            const uint8_t* cursor=bytes; size_t remaining=size; uint64_t pc=address;
            while(remaining){
                size_t before=remaining;
                if(!p->decode(p->handle,&cursor,&remaining,&pc,p->instruction)||remaining>=before){p->halt(uc,DECODE_ERROR);return;}
                ++count;
            }
            ++p->decodes;
            // Cache lifetime is bounded. Exact bytes are checked even on a cache hit.
            if(p->cache.size()>=32768||p->bytes+size>32u*1024*1024){p->cache.clear();p->bytes=0;}
            auto& entry=p->cache[key];
            p->bytes-=entry.bytes.size();entry.bytes.assign(bytes,bytes+size);p->bytes+=size;entry.instructions=count;
        }
        if(count>p->total_limit-p->total){p->halt(uc,TOTAL);return;}
        if(p->slice&&count>p->slice_limit-p->slice){p->halt(uc,SLICE);return;}
        // Charge the entire block before entering it. A code/API hook may stop
        // midway, so this is a conservative upper bound, not retired instructions.
        p->total+=count;p->slice+=count;++p->blocks;
    }catch(...){p->halt(uc,HOST_ERROR);}
}
