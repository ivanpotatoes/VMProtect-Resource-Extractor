#define NOMINMAX
#include <windows.h>
#include <objbase.h>
#include "_plugins.h"
#include "_scriptapi_module.h"
#include "backend.h"
#include "ui.h"
#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstring>
#include <filesystem>
#include <functional>
#include <iomanip>
#include <mutex>
#include <sstream>
#include <thread>

namespace {
HINSTANCE instance=nullptr;
int pluginHandle=0;
std::atomic<bool> stopping=false,busy=false;
std::atomic<uint64_t> generation=1,pauses=0;
std::atomic<HWND> dispatcher=nullptr;
std::thread worker,uiThread;
std::mutex stateMutex,jobMutex;
std::condition_variable jobWake;
std::function<void()> queuedJob;
vreui::ViewState view;
vre::SnapshotPtr snapshot;
uint64_t snapshotGeneration=0;
DWORD snapshotPid=0;
bool lastOk=false;
std::wstring lastOutput;
constexpr UINT Show=WM_APP+41,Update=WM_APP+42,Shutdown=WM_APP+43;
constexpr wchar_t WindowClass[]=L"VMPResourceExtractor.Dispatcher";

std::wstring wide(const std::string& s) {
    if(s.empty()) return {};
    int n=MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,s.data(),int(s.size()),nullptr,0);
    if(!n) throw std::runtime_error("Invalid UTF-8 text");
    std::wstring r(n,L'\0'); MultiByteToWideChar(CP_UTF8,0,s.data(),int(s.size()),r.data(),n); return r;
}
std::wstring wideError(const char* text) {
    if(!text) return L"Unknown failure";
    int n=MultiByteToWideChar(CP_UTF8,0,text,-1,nullptr,0);
    if(n<=1) return L"Unknown failure";
    std::wstring out(size_t(n),L'\0');
    MultiByteToWideChar(CP_UTF8,0,text,-1,out.data(),n);out.pop_back();return out;
}
std::string narrow(const std::wstring& s) {
    if(s.empty()) return {};
    int n=WideCharToMultiByte(CP_UTF8,WC_ERR_INVALID_CHARS,s.data(),int(s.size()),nullptr,0,nullptr,nullptr);
    if(!n) return "Invalid text";
    std::string r(n,'\0'); WideCharToMultiByte(CP_UTF8,0,s.data(),int(s.size()),r.data(),n,nullptr,nullptr); return r;
}
std::wstring hex(uint64_t v) {std::wostringstream s;s<<L"0x"<<std::hex<<std::uppercase<<v;return s.str();}
void notify() {if(HWND w=dispatcher.load()) PostMessageW(w,Update,0,0);}
void status(const std::wstring& text,bool log=true) {
    {std::lock_guard<std::mutex> lock(stateMutex);view.status=text;}
    notify(); if(log) _plugin_logprintf("[VRE] %s\n",narrow(text).c_str());
}
void clearSnapshotLocked() {snapshot.reset();snapshotGeneration=0;snapshotPid=0;view.candidates.clear();view.selectedCandidate=SIZE_MAX;}
void invalidate(const wchar_t* message,bool clearModules=false) {
    ++generation;
    {std::lock_guard<std::mutex> lock(stateMutex);clearSnapshotLocked();lastOk=false;
     if(clearModules){view.modules.clear();view.selectedModule=0;}
     if(!busy) view.status=message;}
    notify();
}
vre::Module moduleAt(uint64_t address) {
    Script::Module::ModuleInfo m{};
    bool ok=address?Script::Module::InfoFromAddr(duint(address),&m):Script::Module::GetMainModuleInfo(&m);
    if(!DbgIsDebugging()||!ok) throw std::runtime_error("No loaded module selected");
    return {m.base,m.size,wide(m.name),wide(m.path)};
}
std::wstring newOutput(const vre::Module& m) {
    SYSTEMTIME t{};GetLocalTime(&t);
    wchar_t suffix[80]{};swprintf_s(suffix,L".resources-%04u%02u%02u-%02u%02u%02u",t.wYear,t.wMonth,t.wDay,t.wHour,t.wMinute,t.wSecond);
    std::filesystem::path path(m.path);
    if(path.empty()) path=std::filesystem::current_path()/m.name;
    path+=suffix;
    auto initial=path;
    for(unsigned i=1;std::filesystem::exists(path);++i) {path=initial;path+=L"-"+std::to_wstring(i);}
    return path.wstring();
}
void refreshModules() {
    std::vector<vreui::ModuleChoice> choices;
    uint64_t main=0;
    if(DbgIsDebugging()) {
        main=Script::Module::GetMainModuleBase();
        BridgeList<Script::Module::ModuleInfo> modules;
        if(!Script::Module::GetList(&modules)) throw std::runtime_error("Could not list loaded modules");
        for(int i=0;i<modules.Count();++i) {
            const auto& m=modules[i];
            choices.push_back({wide(m.name)+L"  ["+hex(m.base)+L"]"+(m.base==main?L"  (main)":L""),m.base});
        }
        std::stable_sort(choices.begin(),choices.end(),[main](const auto&a,const auto&b){return (a.base==main)>(b.base==main);});
    }
    uint64_t selected=0;bool needOutput=false;
    {std::lock_guard<std::mutex> lock(stateMutex);
     view.modules=std::move(choices);
     auto match=std::find_if(view.modules.begin(),view.modules.end(),[](const auto& m){return m.base==view.selectedModule;});
     if(match==view.modules.end()){view.selectedModule=view.modules.empty()?0:view.modules.front().base;clearSnapshotLocked();}
     selected=view.selectedModule;needOutput=view.output.empty();}
    if(selected&&needOutput){auto value=newOutput(moduleAt(selected));std::lock_guard<std::mutex> lock(stateMutex);if(view.output.empty())view.output=value;}
    notify();
}
void pauseForCapture() {
    if(!DbgIsDebugging()) throw std::runtime_error("Load or attach to a program first");
    if(!DbgIsRunning()) return;
    const DWORD pid=DbgGetProcessId(); const uint64_t ticket=pauses.load();
    status(L"Pausing the target for a consistent memory snapshot...");
    // This runs on our worker, outside x64dbg's command callback. Execute the
    // pause request here so capture does not depend on command-queue progress.
    if(!DbgCmdExecDirect("pause")) throw std::runtime_error("Could not request pause");
    const auto until=std::chrono::steady_clock::now()+std::chrono::seconds(8);
    while(std::chrono::steady_clock::now()<until) {
        if(stopping||!DbgIsDebugging()||DbgGetProcessId()!=pid) throw std::runtime_error("Debug session changed while pausing");
        if(!DbgIsRunning()&&pauses.load()>ticket) return;
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    throw std::runtime_error("Pause did not complete. Pause manually, then scan again");
}
void scan(uint64_t selected) {
    {std::lock_guard<std::mutex> lock(stateMutex);clearSnapshotLocked();}
    pauseForCapture(); refreshModules();
    const auto epoch=generation.load(); const DWORD pid=DbgGetProcessId();
    auto valid=[epoch,pid] {return !stopping&&generation.load()==epoch&&DbgIsDebugging()&&!DbgIsRunning()&&DbgGetProcessId()==pid;};
    if(!valid())throw std::runtime_error("Debug session changed before capture");
    const auto mod=moduleAt(selected);
    if(!valid())throw std::runtime_error("Debug session changed while selecting the module");
    status(L"Reading and scanning "+mod.name+L"...");
    auto found=vre::capture(mod,[](uint64_t a,void* p,size_t n){return DbgMemRead(duint(a),p,duint(n));},valid);
    if(!valid()) throw std::runtime_error("Target resumed or changed during capture. Scan again while paused");
    auto items=vre::candidates(found);
    if(items.empty()) throw std::runtime_error("No supported resource table found. Run past unpacking, pause and scan again");
    {std::lock_guard<std::mutex> lock(stateMutex);
     if(generation.load()!=epoch) throw std::runtime_error("Debug session changed during capture");
     snapshot=found;snapshotGeneration=epoch;snapshotPid=pid;view.selectedModule=mod.base;
     view.candidates.clear();
     for(size_t i=0;i<items.size();++i){const auto& c=items[i];view.candidates.push_back({hex(c.tableRva)+L"  |  "+std::to_wstring(c.resources)+L" resources  |  "+std::to_wstring(c.bytes)+L" bytes",i});}
     view.selectedCandidate=items.size()==1?0:SIZE_MAX;
     if(view.output.empty()) view.output=newOutput(mod);}
    status(L"Found "+std::to_wstring(items.size())+L" table(s). Select a table and extract. Target remains paused.");
    for(size_t i=0;i<items.size();++i) _plugin_logprintf("[VRE] candidate=%llu table=%llX key=%08X resources=%llu bytes=%llu\n",
       static_cast<unsigned long long>(i),static_cast<unsigned long long>(items[i].tableRva),items[i].key,
       static_cast<unsigned long long>(items[i].resources),static_cast<unsigned long long>(items[i].bytes));
}
void extract(uint64_t selected,size_t index,const std::wstring& output) {
    vre::SnapshotPtr copy;
    {std::lock_guard<std::mutex> lock(stateMutex);
     if(!snapshot||snapshotGeneration!=generation.load()||snapshotPid!=DbgGetProcessId()||!DbgIsDebugging()||DbgIsRunning())
       throw std::runtime_error("No current paused snapshot. Scan the module again");
     if(selected&&vre::module(snapshot).base!=selected) throw std::runtime_error("Selected module changed. Scan it first");
     copy=snapshot;}
    if(output.empty()) throw std::runtime_error("Choose a new output directory");
    const auto& choices=vre::candidates(copy);
    if(index==SIZE_MAX) {if(choices.size()!=1) throw std::runtime_error("Multiple tables found. Select a table explicitly");index=0;}
    status(L"Extracting resources from the captured snapshot...");
    auto result=vre::extract_snapshot(copy,index,std::filesystem::path(output));
    {std::lock_guard<std::mutex> lock(stateMutex);lastOutput=result.output.wstring();view.output=lastOutput;}
    status(L"Extracted "+std::to_wstring(result.resources)+L" resources ("+std::to_wstring(result.bytes)+L" bytes).\n"+result.output.wstring());
}
bool submit(std::function<void()> job) {
    if(stopping||busy.exchange(true)){_plugin_logputs("[VRE] An operation is already in progress or the plugin is stopping.");return false;}
    {std::lock_guard<std::mutex> lock(stateMutex);view.busy=true;lastOk=false;}
    const auto epoch=generation.load();
    {std::lock_guard<std::mutex> lock(jobMutex);queuedJob=[epoch,job=std::move(job)]{
        if(stopping||generation.load()!=epoch)throw std::runtime_error("Debug session changed before the operation started");job();};}
    notify();jobWake.notify_one();return true;
}
void workerMain() {
    for(;;) {
        std::function<void()> job;
        {std::unique_lock<std::mutex> lock(jobMutex);jobWake.wait(lock,[]{return stopping||bool(queuedJob);});
         if(stopping) break;job=std::move(queuedJob);queuedJob={};}
        bool ok=false;
        try {
            try {job();ok=true;} catch(const std::exception& e) {status(L"Error: "+wideError(e.what()));}
            catch(...) {status(L"Error: unexpected extraction failure");}
        } catch(...) {_plugin_logputs("[VRE] Operation failed; could not format the error message.");}
        {std::lock_guard<std::mutex> lock(stateMutex);view.busy=false;lastOk=ok;}
        busy=false;notify();
    }
}
void moduleChanged(uint64_t base) {
    {std::lock_guard<std::mutex> lock(stateMutex);
     if(base!=view.selectedModule){view.selectedModule=base;clearSnapshotLocked();view.status=L"Module changed. Scan after unpacking.";}}
    notify();
}
LRESULT CALLBACK dispatcherProc(HWND w,UINT msg,WPARAM wp,LPARAM lp) {
    if(msg==Show&&!stopping) {vreui::show();msg=Update;}
    if(msg==Update&&!stopping) {vreui::ViewState copy;{std::lock_guard<std::mutex> lock(stateMutex);copy=view;}vreui::update(copy);return 0;}
    if(msg==Shutdown) {vreui::close();DestroyWindow(w);PostQuitMessage(0);return 0;}
    return DefWindowProcW(w,msg,wp,lp);
}
void uiMain() {
    CoInitializeEx(nullptr,COINIT_APARTMENTTHREADED);
    WNDCLASSW cls{};cls.lpfnWndProc=dispatcherProc;cls.hInstance=instance;cls.lpszClassName=WindowClass;
    if(!RegisterClassW(&cls)){_plugin_logputs("[VRE] Could not register the UI dispatcher.");CoUninitialize();return;}
    HWND window=CreateWindowExW(0,WindowClass,L"",0,0,0,0,0,HWND_MESSAGE,nullptr,instance,nullptr);
    if(!window){UnregisterClassW(WindowClass,instance);CoUninitialize();return;}
    vreui::Callbacks callbacks;
    callbacks.refresh=[]{submit([]{refreshModules();status(L"Modules refreshed. Run until unpacking finishes, then scan.");});};
    callbacks.scan=[](uint64_t m){submit([m]{scan(m);});};
    callbacks.extract=[](uint64_t m,size_t i,const std::wstring& p){submit([m,i,p]{extract(m,i,p);});};
    callbacks.moduleChanged=moduleChanged;
    callbacks.outputChanged=[](const std::wstring& p){std::lock_guard<std::mutex> lock(stateMutex);view.output=p;};
    vreui::initialize(instance,nullptr,std::move(callbacks));dispatcher=window;
    if(stopping)PostMessageW(window,Shutdown,0,0);
    MSG message{};
    while(GetMessageW(&message,nullptr,0,0)>0){if(!vreui::translate(&message)){TranslateMessage(&message);DispatchMessageW(&message);}}
    dispatcher=nullptr;vreui::close();UnregisterClassW(WindowClass,instance);CoUninitialize();
}
uint64_t argumentModule(int argc,char** argv,int pos) {
    if(argc<=pos) return 0;
    duint value=0;if(!DbgIsValidExpression(argv[pos])||!DbgValFromString(argv[pos])) throw std::runtime_error("Invalid module expression");
    value=DbgValFromString(argv[pos]);return value;
}
size_t argumentIndex(int argc,char** argv,int pos) {
    if(argc<=pos) return SIZE_MAX;
    if(!argv[pos][0]||argv[pos][0]=='-')throw std::runtime_error("Candidate index must be a nonnegative decimal number");
    size_t used=0;auto value=std::stoull(argv[pos],&used,10);
    if(used!=strlen(argv[pos])) throw std::runtime_error("Candidate index must be a decimal number");return size_t(value);
}
bool commandScan(int argc,char** argv) {try{auto m=argumentModule(argc,argv,1);return submit([m]{scan(m);});}catch(const std::exception&e){_plugin_logprintf("[VRE] %s\n",e.what());return false;}}
bool commandExtract(int argc,char** argv) {try{if(argc<2)throw std::runtime_error("Usage: vre_extract \"new directory\"[, candidate index]");auto p=wide(argv[1]);auto i=argumentIndex(argc,argv,2);return submit([p,i]{extract(0,i,p);});}catch(const std::exception&e){_plugin_logprintf("[VRE] %s\n",e.what());return false;}}
bool commandDump(int argc,char** argv) {try{if(argc<2)throw std::runtime_error("Usage: vre_dump \"new directory\"[, module][, candidate index]");auto p=wide(argv[1]);auto m=argumentModule(argc,argv,2);auto i=argumentIndex(argc,argv,3);return submit([p,m,i]{scan(m);extract(m,i,p);});}catch(const std::exception&e){_plugin_logprintf("[VRE] %s\n",e.what());return false;}}
bool commandUI(int,char**) {if(HWND w=dispatcher.load()){PostMessageW(w,Show,0,0);if(!busy)submit([]{refreshModules();});return true;}return false;}
bool commandStatus(int,char**) {std::lock_guard<std::mutex> lock(stateMutex);_plugin_logprintf("[VRE] busy=%u ok=%u candidates=%llu\n%s\n",busy?1u:0u,lastOk?1u:0u,static_cast<unsigned long long>(view.candidates.size()),narrow(view.status).c_str());return true;}
duint expression(int,const duint*,void* user) {
    switch(reinterpret_cast<uintptr_t>(user)) {
    case 0:return busy?1:0;
    case 1:{std::lock_guard<std::mutex> lock(stateMutex);return lastOk?1:0;}
    case 2:{std::lock_guard<std::mutex> lock(stateMutex);return view.candidates.size();}
    default:return 0;
    }
}
void callback(CBTYPE type,void* data) {
    if(stopping) return;
    if(type==CB_MENUENTRY){int id=static_cast<PLUG_CB_MENUENTRY*>(data)->hEntry;if(id==1)commandUI(0,nullptr);if(id==2)submit([]{scan(0);});if(id==3)commandStatus(0,nullptr);return;}
    if(type==CB_PAUSEDEBUG){++pauses;return;}
    if(type==CB_RESUMEDEBUG){invalidate(L"Target resumed. Scan again before extracting.");return;}
    if(type==CB_INITDEBUG||type==CB_STOPDEBUG||type==CB_STOPPINGDEBUG||type==CB_DETACH||type==CB_EXITPROCESS){invalidate(L"Load a program, run past unpacking, then scan.",true);return;}
    if(type==CB_LOADDLL||type==CB_UNLOADDLL){invalidate(L"Loaded modules changed. Refresh and scan again.");}
}
}

extern "C" __declspec(dllexport) bool pluginit(PLUG_INITSTRUCT* init) {
    pluginHandle=init->pluginHandle;init->sdkVersion=PLUG_SDKVERSION;init->pluginVersion=1;
    strcpy_s(init->pluginName,"VMP Resource Extractor");stopping=false;
    _plugin_registercommand(pluginHandle,"vre_ui",commandUI,false);
    _plugin_registercommand(pluginHandle,"vre_scan",commandScan,true);
    _plugin_registercommand(pluginHandle,"vre_extract",commandExtract,true);
    _plugin_registercommand(pluginHandle,"vre_dump",commandDump,true);
    _plugin_registercommand(pluginHandle,"vre_status",commandStatus,false);
    _plugin_registerexprfunction(pluginHandle,"vre_busy",0,expression,reinterpret_cast<void*>(0));
    _plugin_registerexprfunction(pluginHandle,"vre_ok",0,expression,reinterpret_cast<void*>(1));
    _plugin_registerexprfunction(pluginHandle,"vre_candidates",0,expression,reinterpret_cast<void*>(2));
    for(auto type:{CB_MENUENTRY,CB_INITDEBUG,CB_STOPPINGDEBUG,CB_STOPDEBUG,CB_DETACH,CB_EXITPROCESS,CB_RESUMEDEBUG,CB_PAUSEDEBUG,CB_LOADDLL,CB_UNLOADDLL})_plugin_registercallback(pluginHandle,type,callback);
    try{worker=std::thread(workerMain);uiThread=std::thread(uiMain);}catch(...){stopping=true;jobWake.notify_all();if(worker.joinable())worker.join();return false;}
    _plugin_logputs("[VRE] Loaded. Plugins > VMP Resource Extractor > Extract resources. Read-only memory capture; no driver or guest hooks.");return true;
}
extern "C" __declspec(dllexport) void plugsetup(PLUG_SETUPSTRUCT* setup) {
    _plugin_menuaddentry(setup->hMenu,1,"Extract resources...");
    _plugin_menuaddentry(setup->hMenu,2,"Scan main module");
    _plugin_menuaddseparator(setup->hMenu);
    _plugin_menuaddentry(setup->hMenu,3,"Status");
}
extern "C" __declspec(dllexport) bool plugstop() {
    stopping=true;++generation;jobWake.notify_all();
    if(HWND w=dispatcher.load())PostMessageW(w,Shutdown,0,0);
    if(worker.joinable())worker.join();
    if(uiThread.joinable())uiThread.join();
    for(auto name:{"vre_ui","vre_scan","vre_extract","vre_dump","vre_status"})_plugin_unregistercommand(pluginHandle,name);
    for(auto name:{"vre_busy","vre_ok","vre_candidates"})_plugin_unregisterexprfunction(pluginHandle,name);
    {std::lock_guard<std::mutex> lock(stateMutex);clearSnapshotLocked();}
    return true;
}
BOOL WINAPI DllMain(HINSTANCE h,DWORD reason,LPVOID) {if(reason==DLL_PROCESS_ATTACH)instance=h;return TRUE;}
