#include "ui.h"
#include "resource.h"
#include <commctrl.h>
#include <shobjidl.h>
#include <algorithm>
#include <filesystem>
#include <stdexcept>
#include <type_traits>
#include <utility>

namespace vreui {
namespace {
HINSTANCE moduleInstance=nullptr;
HWND ownerWindow=nullptr,dialogWindow=nullptr,tooltipWindow=nullptr;
IFileOpenDialog* activePicker=nullptr;
Callbacks actions;
ViewState state;
bool applying=false;
std::wstring lastOutput;
constexpr size_t noCandidate=(std::numeric_limits<size_t>::max)();
constexpr wchar_t scanHelp[]=L"Run until unpacking finishes, then scan. A running target is paused for capture and left paused. Select the EXE or DLL that owns the resources. A valid table alone cannot prove that unpacking has finished.";
constexpr wchar_t outputHelp[]=L"Resources are written to a new folder with manifest.json. Existing folders are never overwritten. Browse selects a parent folder and suggests an unused child folder.";

std::wstring text(int id) {
    HWND control=GetDlgItem(dialogWindow,id);
    const int count=GetWindowTextLengthW(control);
    std::wstring value(static_cast<size_t>(count)+1,L'\0');
    const int copied=GetWindowTextW(control,value.data(),count+1);
    value.resize(static_cast<size_t>((std::max)(copied,0)));
    return value;
}
uint64_t selectedModule() {
    const LRESULT row=SendDlgItemMessageW(dialogWindow,IDC_VRE_MODULE,CB_GETCURSEL,0,0);
    return row>=0 && static_cast<size_t>(row)<state.modules.size()?state.modules[static_cast<size_t>(row)].base:0;
}
size_t selectedCandidate() {
    const LRESULT row=SendDlgItemMessageW(dialogWindow,IDC_VRE_TABLE,CB_GETCURSEL,0,0);
    return row>=0 && static_cast<size_t>(row)<state.candidates.size()?state.candidates[static_cast<size_t>(row)].index:noCandidate;
}
void enableControls() {
    const bool idle=!state.busy;
    for(int id:{IDC_VRE_MODULE,IDC_VRE_REFRESH,IDC_VRE_OUTPUT,IDC_VRE_BROWSE})
        EnableWindow(GetDlgItem(dialogWindow,id),idle);
    EnableWindow(GetDlgItem(dialogWindow,IDC_VRE_TABLE),idle&&!state.candidates.empty());
    EnableWindow(GetDlgItem(dialogWindow,IDC_VRE_SCAN),idle&&selectedModule()!=0);
    EnableWindow(GetDlgItem(dialogWindow,IDC_VRE_EXTRACT),idle&&selectedModule()!=0&&selectedCandidate()!=noCandidate&&!text(IDC_VRE_OUTPUT).empty());
}
template<class T> bool sameChoices(const std::vector<T>& a,const std::vector<T>& b) {
    if(a.size()!=b.size()) return false;
    for(size_t i=0;i<a.size();++i) {
        if(a[i].label!=b[i].label) return false;
        if constexpr(std::is_same_v<T,ModuleChoice>) { if(a[i].base!=b[i].base) return false; }
        else { if(a[i].index!=b[i].index) return false; }
    }
    return true;
}
void render(const ViewState& next,bool initial=false) {
    const uint64_t oldModule=initial?0:selectedModule();
    const size_t oldCandidate=initial?noCandidate:selectedCandidate();
    const bool modulesChanged=initial||!sameChoices(state.modules,next.modules);
    const bool moduleChanged=next.selectedModule&&next.selectedModule!=oldModule;
    const bool candidatesChanged=initial||moduleChanged||!sameChoices(state.candidates,next.candidates);
    applying=true;
    state=next;
    if(modulesChanged) {
        SendDlgItemMessageW(dialogWindow,IDC_VRE_MODULE,CB_RESETCONTENT,0,0);
        for(const auto& choice:state.modules)
            SendDlgItemMessageW(dialogWindow,IDC_VRE_MODULE,CB_ADDSTRING,0,reinterpret_cast<LPARAM>(choice.label.c_str()));
    }
    if(modulesChanged||state.selectedModule) {
        const uint64_t wanted=state.selectedModule?state.selectedModule:oldModule;
        size_t row=0;
        for(size_t i=0;i<state.modules.size();++i) if(state.modules[i].base==wanted) { row=i;break; }
        SendDlgItemMessageW(dialogWindow,IDC_VRE_MODULE,CB_SETCURSEL,state.modules.empty()?static_cast<WPARAM>(-1):row,0);
    }
    if(candidatesChanged) {
        SendDlgItemMessageW(dialogWindow,IDC_VRE_TABLE,CB_RESETCONTENT,0,0);
        for(const auto& choice:state.candidates)
            SendDlgItemMessageW(dialogWindow,IDC_VRE_TABLE,CB_ADDSTRING,0,reinterpret_cast<LPARAM>(choice.label.c_str()));
    }
    if(candidatesChanged||state.selectedCandidate!=noCandidate) {
        // A new scan with no explicit selection must not silently choose the
        // first of several valid tables. Ordinary progress updates preserve a
        // selection the user already made in an unchanged list.
        const size_t wanted=state.selectedCandidate!=noCandidate?state.selectedCandidate:
            (candidatesChanged?noCandidate:oldCandidate);
        WPARAM row=static_cast<WPARAM>(-1);
        if(wanted!=noCandidate) {
            for(size_t i=0;i<state.candidates.size();++i)
                if(state.candidates[i].index==wanted) { row=i;break; }
        }
        SendDlgItemMessageW(dialogWindow,IDC_VRE_TABLE,CB_SETCURSEL,row,0);
    }
    if(initial||state.output!=lastOutput) {
        SetDlgItemTextW(dialogWindow,IDC_VRE_OUTPUT,state.output.c_str());
        lastOutput=state.output;
    }
    SetDlgItemTextW(dialogWindow,IDC_VRE_STATUS,state.status.c_str());
    applying=false;
    enableControls();
}
void addTip(int id,const wchar_t* value) {
    TOOLINFOW tool{};
    tool.cbSize=sizeof(tool); tool.uFlags=TTF_IDISHWND|TTF_SUBCLASS;
    tool.hwnd=dialogWindow; tool.uId=reinterpret_cast<UINT_PTR>(GetDlgItem(dialogWindow,id));
    tool.lpszText=const_cast<wchar_t*>(value);
    SendMessageW(tooltipWindow,TTM_ADDTOOLW,0,reinterpret_cast<LPARAM>(&tool));
}
void createTips() {
    tooltipWindow=CreateWindowExW(WS_EX_TOPMOST|WS_EX_NOACTIVATE,TOOLTIPS_CLASSW,nullptr,
        WS_POPUP|TTS_ALWAYSTIP|TTS_NOPREFIX,CW_USEDEFAULT,CW_USEDEFAULT,CW_USEDEFAULT,CW_USEDEFAULT,
        dialogWindow,nullptr,moduleInstance,nullptr);
    if(!tooltipWindow) return;
    SendMessageW(tooltipWindow,WM_SETFONT,SendMessageW(dialogWindow,WM_GETFONT,0,0),FALSE);
    SendMessageW(tooltipWindow,TTM_SETMAXTIPWIDTH,0,MulDiv(350,GetDpiForWindow(dialogWindow),96));
    SendMessageW(tooltipWindow,TTM_SETDELAYTIME,TTDT_INITIAL,300);
    SendMessageW(tooltipWindow,TTM_SETDELAYTIME,TTDT_AUTOPOP,20000);
    for(int id:{IDC_VRE_HELP_SCAN,IDC_VRE_SCAN,IDC_VRE_TABLE}) addTip(id,scanHelp);
    for(int id:{IDC_VRE_HELP_OUTPUT,IDC_VRE_OUTPUT,IDC_VRE_BROWSE}) addTip(id,outputHelp);
    addTip(IDC_VRE_MODULE,L"Select the main EXE or a loaded DLL. Refresh updates the list of loaded modules.");
    addTip(IDC_VRE_STATUS,LPSTR_TEXTCALLBACKW);
}
void browse() {
    const HRESULT apartment=CoInitializeEx(nullptr,COINIT_APARTMENTTHREADED);
    IFileOpenDialog* picker=nullptr;
    HRESULT result=CoCreateInstance(CLSID_FileOpenDialog,nullptr,CLSCTX_INPROC_SERVER,IID_PPV_ARGS(&picker));
    if(SUCCEEDED(result)) {
        DWORD flags=0;
        result=picker->GetOptions(&flags);
        if(SUCCEEDED(result)) result=picker->SetOptions(flags|FOS_PICKFOLDERS|FOS_FORCEFILESYSTEM|FOS_PATHMUSTEXIST);
        if(SUCCEEDED(result)) result=picker->SetTitle(L"Choose an output parent folder");
        if(SUCCEEDED(result)) {
            activePicker=picker;
            result=picker->Show(dialogWindow);
            activePicker=nullptr;
        }
        if(SUCCEEDED(result)) {
            IShellItem* item=nullptr;
            result=picker->GetResult(&item);
            if(SUCCEEDED(result)) {
                PWSTR folder=nullptr;
                result=item->GetDisplayName(SIGDN_FILESYSPATH,&folder);
                if(SUCCEEDED(result)) {
                    try {
                        std::filesystem::path leaf=std::filesystem::path(text(IDC_VRE_OUTPUT)).filename();
                        if(leaf.empty()||leaf==L"."||leaf==L"..") leaf=L"extracted-resources";
                        std::filesystem::path target=std::filesystem::path(folder)/leaf;
                        const auto original=target;
                        unsigned suffix=2;
                        while(std::filesystem::exists(target)&&suffix<10000)
                            target=std::filesystem::path(original.wstring()+L"-"+std::to_wstring(suffix++));
                        if(std::filesystem::exists(target)) throw std::runtime_error("No unused output name");
                        SetDlgItemTextW(dialogWindow,IDC_VRE_OUTPUT,target.c_str());
                    } catch(const std::exception&) {
                        MessageBoxW(dialogWindow,L"Could not select a new output folder. Enter a new folder path manually.",L"VMProtect Resource Extractor",MB_OK|MB_ICONERROR);
                    }
                    CoTaskMemFree(folder);
                }
                item->Release();
            }
        }
        picker->Release();
    }
    if(SUCCEEDED(apartment)) CoUninitialize();
    if(FAILED(result)&&result!=HRESULT_FROM_WIN32(ERROR_CANCELLED))
        MessageBoxW(dialogWindow,L"The folder browser could not open. Enter the output folder path manually.",L"VMProtect Resource Extractor",MB_OK|MB_ICONERROR);
}
INT_PTR CALLBACK dialogProc(HWND wnd,UINT message,WPARAM wp,LPARAM lp) {
    if(message==WM_INITDIALOG) {
        dialogWindow=wnd;
        SendMessageW(wnd,WM_SETICON,ICON_SMALL,reinterpret_cast<LPARAM>(LoadIconW(nullptr,IDI_APPLICATION)));
        SendMessageW(wnd,WM_SETICON,ICON_BIG,reinterpret_cast<LPARAM>(LoadIconW(nullptr,IDI_APPLICATION)));
        SendDlgItemMessageW(wnd,IDC_VRE_OUTPUT,EM_SETLIMITTEXT,32767,0);
        const ViewState initial=state;
        render(initial,true); createTips();
        return TRUE;
    }
    if(message==WM_COMMAND&&!applying) {
        const int id=LOWORD(wp),notification=HIWORD(wp);
        if(id==IDC_VRE_MODULE&&notification==CBN_SELCHANGE) {
            const uint64_t base=selectedModule();
            state.selectedModule=base;
            state.candidates.clear();state.selectedCandidate=noCandidate;
            SendDlgItemMessageW(wnd,IDC_VRE_TABLE,CB_RESETCONTENT,0,0);
            state.status=L"Scan the selected module to find its protected resources.";
            SetDlgItemTextW(wnd,IDC_VRE_STATUS,state.status.c_str()); enableControls();
            if(actions.moduleChanged) actions.moduleChanged(base);
            return TRUE;
        }
        if(id==IDC_VRE_TABLE&&notification==CBN_SELCHANGE) { state.selectedCandidate=selectedCandidate();enableControls();return TRUE; }
        if(id==IDC_VRE_OUTPUT&&notification==EN_CHANGE) {
            state.output=text(IDC_VRE_OUTPUT);enableControls();
            if(actions.outputChanged) actions.outputChanged(state.output);
            return TRUE;
        }
        if(id==IDCANCEL) { DestroyWindow(wnd);return TRUE; }
        if(id==IDC_VRE_ABOUT) {
            MessageBoxW(wnd,L"VMProtect Resource Extractor\n\nCreator: Ivan Kozlovsky\ncontact@ivankozlovsky.com\nivankozlovsky.com\n\nExtract protected resources from a paused EXE or DLL.",L"About VMProtect Resource Extractor",MB_OK|MB_ICONINFORMATION);
            return TRUE;
        }
        if(id==IDC_VRE_HELP_SCAN||id==IDC_VRE_HELP_OUTPUT) {
            MessageBoxW(wnd,id==IDC_VRE_HELP_SCAN?scanHelp:outputHelp,L"VMProtect Resource Extractor",MB_OK|MB_ICONINFORMATION);return TRUE;
        }
        if(state.busy) return FALSE;
        if(id==IDC_VRE_BROWSE) { browse();return TRUE; }
        if(id==IDC_VRE_REFRESH) { if(actions.refresh) actions.refresh();return TRUE; }
        if(id==IDC_VRE_SCAN) { const auto base=selectedModule();if(base&&actions.scan) actions.scan(base);return TRUE; }
        if(id==IDC_VRE_EXTRACT) {
            const auto base=selectedModule();const auto candidate=selectedCandidate();
            const auto output=text(IDC_VRE_OUTPUT);
            if(base&&candidate!=noCandidate&&!output.empty()&&actions.extract) actions.extract(base,candidate,output);
            return TRUE;
        }
    }
    if(message==WM_NOTIFY) {
        auto* header=reinterpret_cast<NMHDR*>(lp);
        if(header&&header->code==TTN_GETDISPINFOW) {
            auto* tip=reinterpret_cast<NMTTDISPINFOW*>(lp);
            tip->lpszText=const_cast<wchar_t*>(state.status.c_str());return TRUE;
        }
    }
    if(message==WM_CTLCOLORSTATIC) {
        const int id=GetDlgCtrlID(reinterpret_cast<HWND>(lp));
        if(id==IDC_VRE_HELP_SCAN||id==IDC_VRE_HELP_OUTPUT) {
            SetTextColor(reinterpret_cast<HDC>(wp),RGB(0,72,130));SetBkMode(reinterpret_cast<HDC>(wp),TRANSPARENT);
            return reinterpret_cast<INT_PTR>(GetSysColorBrush(COLOR_3DFACE));
        }
    }
    if(message==WM_CLOSE) { DestroyWindow(wnd);return TRUE; }
    if(message==WM_DESTROY) {
        if(tooltipWindow) { DestroyWindow(tooltipWindow);tooltipWindow=nullptr; }
        dialogWindow=nullptr;return TRUE;
    }
    return FALSE;
}
}

void initialize(HINSTANCE instance,HWND owner,Callbacks callbacks) {
    moduleInstance=instance;ownerWindow=owner;actions=std::move(callbacks);
    INITCOMMONCONTROLSEX controls{sizeof(controls),ICC_STANDARD_CLASSES};
    InitCommonControlsEx(&controls);
}
bool show() {
    if(dialogWindow) { ShowWindow(dialogWindow,SW_RESTORE);SetForegroundWindow(dialogWindow);return true; }
    HWND created=CreateDialogParamW(moduleInstance,MAKEINTRESOURCEW(IDD_VRE),ownerWindow,dialogProc,0);
    if(!created) return false;
    ShowWindow(created,SW_SHOW);SetForegroundWindow(created);return true;
}
void close() {
    if(activePicker) activePicker->Close(HRESULT_FROM_WIN32(ERROR_CANCELLED));
    const HWND parent=dialogWindow;
    if(parent) {
        EnumThreadWindows(GetCurrentThreadId(),[](HWND wnd,LPARAM owner)->BOOL {
            if(GetWindow(wnd,GW_OWNER)==reinterpret_cast<HWND>(owner)) SendMessageW(wnd,WM_CLOSE,0,0);
            return TRUE;
        },reinterpret_cast<LPARAM>(parent));
        if(IsWindow(parent)) DestroyWindow(parent);
    }
}
void update(const ViewState& next) { if(dialogWindow) render(next);else state=next; }
bool is_open() { return dialogWindow!=nullptr; }
HWND window() { return dialogWindow; }
bool translate(MSG* message) {
    return message&&dialogWindow&&(message->hwnd==dialogWindow||IsChild(dialogWindow,message->hwnd))&&IsDialogMessageW(dialogWindow,message)!=FALSE;
}
}
