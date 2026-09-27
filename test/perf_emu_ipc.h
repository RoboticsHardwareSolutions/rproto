#ifndef __PERF_EMU_IPC_H__
#define __PERF_EMU_IPC_H__

#include "stdbool.h"
#include "pthread.h"

// Forward declaration - full struct in perf_emu.h
struct perf_emu_instance_data;

bool perf_emu_mutex_init(void);
bool perf_emu_enter_critical_section(void);
bool perf_emu_leave_critical_section(void);
bool perf_emu_mutex_delete(void);

// Check if packet should be dropped based on noise config
bool perf_emu_noisy_should_drop(const struct perf_emu_instance_data* data);

// Check if response should be sent with corrupted CRC based on noise config
bool perf_emu_noisy_should_corrupt(const struct perf_emu_instance_data* data);

#endif  // __PERF_EMU_IPC_H__
