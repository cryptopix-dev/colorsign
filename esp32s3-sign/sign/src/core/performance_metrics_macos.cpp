#ifdef __APPLE__

#include <mach/mach.h>
#include <mach/mach_time.h>
#include <unistd.h>

namespace clwe {

// macOS-specific memory measurement
MemoryStats PerformanceMetrics::get_memory_usage_impl() {
    struct task_basic_info info;
    mach_msg_type_number_t infoCount = TASK_BASIC_INFO_COUNT;
    if (task_info(mach_task_self(), TASK_BASIC_INFO, (task_info_t)&info, &infoCount) != KERN_SUCCESS) {
        return {0, 0, 0};
    }

    // Simplified: current = resident_size, peak = resident_size, average = resident_size
    return {info.resident_size, info.resident_size, info.resident_size};
}

// macOS-specific CPU cycle counting (using mach_absolute_time as approximation)
uint64_t PerformanceMetrics::get_cpu_cycles_impl() {
    static mach_timebase_info_data_t timebase;
    if (timebase.denom == 0) {
        mach_timebase_info(&timebase);
    }
    return mach_absolute_time() * timebase.numer / timebase.denom;
}

} // namespace clwe

#endif