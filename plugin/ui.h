#pragma once
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <limits>
#include <string>
#include <vector>

namespace vreui {
struct ModuleChoice { std::wstring label; uint64_t base=0; };
struct CandidateChoice { std::wstring label; size_t index=0; };
struct ViewState {
    std::vector<ModuleChoice> modules;
    std::vector<CandidateChoice> candidates;
    std::wstring output;
    std::wstring status=L"Load a program, then scan after it has unpacked.";
    bool busy=false;
    uint64_t selectedModule=0; // Zero preserves the current selection.
    size_t selectedCandidate=(std::numeric_limits<size_t>::max)();
};
struct Callbacks {
    std::function<void()> refresh;
    std::function<void(uint64_t)> scan;
    std::function<void(uint64_t,size_t,const std::wstring&)> extract;
    std::function<void(uint64_t)> moduleChanged;
    std::function<void(const std::wstring&)> outputChanged;
};

// Call these on the plugin's dedicated UI thread. Pass its message-pump MSG
// through translate() before TranslateMessage/DispatchMessage.
void initialize(HINSTANCE instance,HWND owner,Callbacks callbacks);
bool show();
void close();
void update(const ViewState& state);
bool is_open();
HWND window();
bool translate(MSG* message);
}
