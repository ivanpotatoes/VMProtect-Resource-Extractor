#include "../plugin/backend.h"
#include <algorithm>
#include <cstring>
#include <fstream>
#include <iostream>
#include <iterator>
#include <string>
#include <vector>

int wmain(int argc,wchar_t** argv) {
    try {
        if(argc<4) throw std::runtime_error("memory-image output base [mode] [value]");
        const std::filesystem::path input=argv[1], output=argv[2];
        const uint64_t base=std::stoull(argv[3],nullptr,0);
        const std::wstring mode=argc>4?argv[4]:L"normal";
        const uint64_t value=argc>5?std::stoull(argv[5],nullptr,0):0;
        std::ifstream file(input,std::ios::binary);
        std::vector<unsigned char> memory((std::istreambuf_iterator<char>(file)),{});
        if(!file || memory.empty()) throw std::runtime_error("Cannot read test memory image");
        size_t reads=0, headerReads=0;
        vre::Module selected{base,memory.size(),L"memory-fixture.exe",input.wstring()};
        auto snapshot=vre::capture(selected,[&](uint64_t address,void* buffer,size_t size) {
            ++reads;
            if(address<base || address-base>memory.size() || size>memory.size()-(address-base)) return false;
            const uint64_t offset=address-base;
            if(mode==L"blocked" && offset<value+4096 && value<offset+size) return false;
            std::memcpy(buffer,memory.data()+offset,size);
            if(offset==0) {
                ++headerReads;
                if((headerReads>=5 && mode==L"changed") || (headerReads>=3 && mode==L"early-change"))
                    static_cast<unsigned char*>(buffer)[0]^=1;
            }
            return true;
        },[&] { return mode!=L"cancel" || reads<value; });
        const auto& list=vre::candidates(snapshot);
        std::cout<<"candidates="<<list.size()<<" reads="<<reads<<"\n";
        if(mode==L"list") return 0;
        if(list.empty()) throw std::runtime_error("No resource table found");
        if(mode==L"freeze") std::fill(memory.begin(),memory.end(),static_cast<unsigned char>(0));
        const size_t index=mode==L"select"?size_t(value):0;
        const auto result=vre::extract_snapshot(snapshot,index,output);
        std::cout<<"resources="<<result.resources<<" bytes="<<result.bytes<<"\n";
        return 0;
    } catch(const std::exception& error) {
        std::cerr<<"error: "<<error.what()<<"\n";
        return 1;
    }
}
