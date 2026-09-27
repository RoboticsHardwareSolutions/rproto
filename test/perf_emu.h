#ifndef __PERF_EMU_H__
#define __PERF_EMU_H__

#include "stdbool.h"
#include "rproto.h"

// Number of virtual radio pairs for performance testing
#define PERF_EMU_DEVICE_NUM 3

// Unique ID for device identification
#define PERF_EMU_UNIQUE_ID {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66}

typedef enum
{
    perf_emu_unknown_mode,
    perf_emu_echo_mode,           // Echo received packets back
    perf_emu_req_resp_mode,       // Request/Response mode (like broker)
    perf_emu_noisy_traffic_mode,  // Noisy traffic simulation (packet loss, corruption)
} perf_emu_mode;

// Configuration for noisy mode
typedef struct
{
    double packet_loss_percent;  // 0.0 - 100.0
    double crc_error_percent;    // 0.0 - 100.0
    int    min_delay_ms;         // Minimum delay between packets
    int    max_delay_ms;         // Maximum delay between packets
} perf_emu_noisy_config;

// Instance data for each device
struct perf_emu_instance_data
{
    bool                  send_client_data;
    bool                  reset_results;
    perf_emu_mode         actual_mode;
    pthread_t             emu_thread;
    rproto_serial         serial;
    char                  port_name[30];
    rproto_packet         buf;
    int                   device_num;
    perf_emu_noisy_config noisy_config;  // Used in noisy traffic mode
};

// Instance results for monitoring
struct perf_emu_instance_results
{
    uint64_t packets_received;
    uint64_t packets_sent;
    uint64_t crc_errors_detected;  // frames sent with corrupted CRC (noisy mode)
    uint64_t bytes_transferred;
};

// Statistics structure for test results (forward declaration)
typedef struct
{
    double   throughput_kbps;
    double   latency_avg_us;
    double   latency_min_us;
    double   latency_max_us;
    uint64_t packets_sent;
    uint64_t packets_received;
    double   packet_loss_percent;
} perf_test_results;

// Initialize the emulator system
bool perf_emu_start(void);

// Stop all emulators
void perf_emu_stop(void);

// Setup mode for a specific device
void perf_emu_setup_mode(int device_num, perf_emu_mode mode);

// Setup noisy traffic configuration
void perf_emu_setup_noisy_config(int device_num, const perf_emu_noisy_config* config);

// Start emulating traffic
bool perf_emu_start_traffic(int device_num);

// Get statistics for a device
struct perf_emu_instance_results perf_emu_get_stats(int device_num);

// Reset statistics for a device
void perf_emu_reset_stats(int device_num);

#endif
