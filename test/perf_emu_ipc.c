#include "perf_emu_ipc.h"
#include "pthread.h"
#include "rlog.h"
#include "perf_emu.h"

// External functions from perf_emu.c
extern double rand_double(void);

pthread_mutex_t     perf_emu_mutex;
pthread_mutexattr_t perf_emu_attr;

bool perf_emu_enter_critical_section(void)
{
    if (pthread_mutex_lock(&perf_emu_mutex) != 0)
    {
        RLOG_ERROR("cannot lock perf_emu mutex");
        return false;
    }
    return true;
}

bool perf_emu_leave_critical_section(void)
{
    if (pthread_mutex_unlock(&perf_emu_mutex) != 0)
    {
        RLOG_ERROR("cannot unlock perf_emu mutex");
        return false;
    }
    return true;
}

bool perf_emu_mutex_delete(void)
{
    if (pthread_mutex_destroy(&perf_emu_mutex) != 0)
    {
        RLOG_ERROR("cannot destroy perf_emu mutex");
        return false;
    }
    return true;
}

bool perf_emu_mutex_init(void)
{
    if (pthread_mutexattr_init(&perf_emu_attr) != 0)
    {
        RLOG_ERROR("cannot init perf_emu mutex attr");
        return false;
    }
    if (pthread_mutexattr_settype(&perf_emu_attr, PTHREAD_MUTEX_RECURSIVE) != 0)
    {
        RLOG_ERROR("cannot init perf_emu mutex");
        return false;
    }
    if (pthread_mutex_init(&perf_emu_mutex, &perf_emu_attr) != 0)
    {
        RLOG_ERROR("cannot init perf_emu mutex");
        return false;
    }
    return true;
}

bool perf_emu_noisy_should_drop(const struct perf_emu_instance_data* data)
{
    return (rand_double() * 100.0 < data->noisy_config.packet_loss_percent);
}

bool perf_emu_noisy_should_corrupt(const struct perf_emu_instance_data* data)
{
    return (rand_double() * 100.0 < data->noisy_config.crc_error_percent);
}
