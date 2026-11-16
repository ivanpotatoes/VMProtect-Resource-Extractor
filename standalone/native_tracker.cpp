// Allocation-free byte coverage tracking for Unicorn memory-write events.
// This DLL does not link Unicorn or modify guest registers/memory. The caller
// owns the state and coverage buffer and must keep both alive until hook removal.
#define NOMINMAX
#pragma warning(push)
#pragma warning(disable: 4505) // Unused static helpers in upstream platform.h.
#include <unicorn/unicorn.h>
#pragma warning(pop)
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <new>
#include <type_traits>

#define VMP_EXPORT extern "C" __declspec(dllexport)

namespace {
constexpr std::uint64_t magic = 0x564d505752495445ull;
struct Tracker {
    std::uint64_t signature;
    std::uint64_t base;
    std::uint64_t size;
    std::uint8_t* written;
    std::uint64_t callbacks;
    std::uint64_t accepted;
    std::uint64_t bytes;
    std::uint64_t generation;
    std::uint64_t rejected;
};

void saturating_add(std::uint64_t& value, std::uint64_t delta) noexcept {
    constexpr auto maximum = std::numeric_limits<std::uint64_t>::max();
    value = delta > maximum - value ? maximum : value + delta;
}

void write_hook(uc_engine*, uc_mem_type access, std::uint64_t address,
                int size, std::int64_t, void* opaque) noexcept {
    auto* tracker = static_cast<Tracker*>(opaque);
    if (!tracker || tracker->signature != magic) return;
    saturating_add(tracker->callbacks, 1);
    // Complete ranges only, matching the original Python tracker. Subtraction
    // avoids overflow at UINT64_MAX; never clamp a partial write into the image.
    if (access != UC_MEM_WRITE || size <= 0 || address < tracker->base) {
        saturating_add(tracker->rejected, 1);
        return;
    }
    const auto offset = address - tracker->base;
    const auto length = static_cast<std::uint64_t>(size);
    if (offset > tracker->size || length > tracker->size - offset) {
        saturating_add(tracker->rejected, 1);
        return;
    }
    std::memset(tracker->written + static_cast<std::size_t>(offset), 1,
                static_cast<std::size_t>(length));
    saturating_add(tracker->accepted, 1);
    saturating_add(tracker->bytes, length);
    // Generation records accepted writes, including rewrites of covered bytes.
    saturating_add(tracker->generation, 1);
}
static_assert(std::is_convertible_v<decltype(&write_hook), uc_cb_hookmem_t>);
}

VMP_EXPORT unsigned vmp_tracker_abi_version() noexcept { return 1; }
VMP_EXPORT std::size_t vmp_tracker_state_size() noexcept { return sizeof(Tracker); }
VMP_EXPORT void* vmp_tracker_callback() noexcept {
    return reinterpret_cast<void*>(&write_hook);
}

// Return 1 on success, 0 on invalid capacity/alignment/range. Initial coverage
// is retained: the caller can mark file-backed bytes before attaching the hook.
VMP_EXPORT int vmp_tracker_init(void* storage, std::size_t storage_size,
                               std::uint64_t base, std::uint64_t size,
                               std::uint8_t* written, std::size_t capacity) noexcept {
    if (!storage || storage_size < sizeof(Tracker) ||
        reinterpret_cast<std::uintptr_t>(storage) % alignof(Tracker) != 0 ||
        !written || size > capacity || size > std::numeric_limits<std::size_t>::max() ||
        (size && size - 1 > std::numeric_limits<std::uint64_t>::max() - base)) return 0;
    new (storage) Tracker{magic, base, size, written, 0, 0, 0, 0, 0};
    return 1;
}

// values: callbacks, accepted writes, accepted bytes (rewrites included),
// generation, rejected writes. Read only when Unicorn is not running.
VMP_EXPORT int vmp_tracker_stats(const void* storage, std::uint64_t* values,
                                std::size_t count) noexcept {
    const auto* tracker = static_cast<const Tracker*>(storage);
    if (!tracker || tracker->signature != magic || !values || count < 5) return 0;
    values[0] = tracker->callbacks;
    values[1] = tracker->accepted;
    values[2] = tracker->bytes;
    values[3] = tracker->generation;
    values[4] = tracker->rejected;
    return 1;
}
