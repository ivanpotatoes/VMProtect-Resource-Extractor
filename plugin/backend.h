#pragma once
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <memory>
#include <string>
#include <vector>

namespace vre {
struct Module {
    uint64_t base=0;
    uint64_t size=0;
    std::wstring name;
    std::wstring path;
};
struct Candidate {
    uint32_t tableRva=0;
    uint32_t key=0;
    size_t resources=0;
    uint64_t bytes=0;
};
class Snapshot;
using SnapshotPtr=std::shared_ptr<Snapshot>;
using ReadMemory=std::function<bool(uint64_t,void*,size_t)>;
using IsValid=std::function<bool()>;

// The caller keeps the selected debug session paused throughout capture.
// A snapshot contains copied image bytes and never reads the target on export.
SnapshotPtr capture(const Module& selected,const ReadMemory& read,const IsValid& valid);
const Module& module(const SnapshotPtr& snapshot);
const std::vector<Candidate>& candidates(const SnapshotPtr& snapshot);

struct ExtractResult {
    std::filesystem::path output;
    size_t resources=0;
    uint64_t bytes=0;
};
ExtractResult extract_snapshot(const SnapshotPtr& snapshot,size_t candidateIndex,
                               const std::filesystem::path& output);
}
