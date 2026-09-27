#include "perf_emu.h"
#include "perf_emu_ipc.h"
#include "pthread.h"
#include "rbase64.h"
#include "rcrc.h"
#include "rproto.h"
#include "rlog.h"
#include "unistd.h"
#include "stdlib.h"
#include "time.h"

#define PERF_EMU_WAIT_TIMEOUT_MS 10
#define NOISY_EMU_JITTER_US 500

volatile bool perf_emu_quit = false;

// Instance data for each device
struct perf_emu_instance_data pei_data[PERF_EMU_DEVICE_NUM] = {{.port_name = "/tmp/perf_emu1_tx"},
                                                               {.port_name = "/tmp/perf_emu2_tx"},
                                                               {.port_name = "/tmp/perf_emu3_tx"}};

// Instance results for monitoring
struct perf_emu_instance_results pei_results[PERF_EMU_DEVICE_NUM];

// Random noise generator state
uint32_t xorshift_state = 12345;

// Simple XORSHIFT random number generator
uint32_t xorshift32(void)
{
    uint32_t x = xorshift_state;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    xorshift_state = x;
    return x;
}

// Generate random double in range [0, 1)
double rand_double(void)
{
    return (double) xorshift32() / (double) 0xFFFFFFFF;
}

// Sleep with jitter
static void noisy_sleep(const perf_emu_noisy_config* config)
{
    if (config->min_delay_ms == 0 && config->max_delay_ms == 0)
    {
        usleep(NOISY_EMU_JITTER_US);
        return;
    }

    uint32_t jitter = (xorshift32() % (config->max_delay_ms - config->min_delay_ms + 1)) * 1000;
    usleep((config->min_delay_ms * 1000) + jitter);
}

// Raw (non-base64) size of a packet frame, used for byte accounting
static uint64_t perf_emu_packet_size(const rproto_packet* pkt)
{
    return sizeof(pkt->preamble) + sizeof(pkt->id) + sizeof(pkt->payload_length) + pkt->payload_length +
           sizeof(pkt->crc);
}

static void perf_emu_add_stats(int device_num, uint64_t received, uint64_t sent, uint64_t crc_errors, uint64_t bytes)
{
    perf_emu_enter_critical_section();
    pei_results[device_num].packets_received += received;
    pei_results[device_num].packets_sent += sent;
    pei_results[device_num].crc_errors_detected += crc_errors;
    pei_results[device_num].bytes_transferred += bytes;
    perf_emu_leave_critical_section();
}

// Build the wire frame (preamble + id + b64 length + base64 payload + CRC) and write it
// with a raw serial transfer. rproto_send_packet() always recomputes the CRC, so this is
// the only way to put a corrupted frame on the line.
static bool perf_emu_send_raw_packet(rproto_serial* serial, const rproto_packet* packet, bool corrupt_crc)
{
    uint8_t frame[sizeof(rproto_packet)];

    memcpy(frame, packet, sizeof(packet->preamble) + sizeof(packet->id));
    unsigned int b64_len = b64_encode(packet->payload, packet->payload_length, &frame[4]);
    frame[3]             = (uint8_t) b64_len;

    size_t   crc_size = 4 + b64_len;
    uint16_t crc      = crc16_ccitt((char*) frame, (int) crc_size);
    if (corrupt_crc)
    {
        crc ^= 0xFFFF;
    }

    frame[crc_size]     = (uint8_t) (crc & 0xFF);
    frame[crc_size + 1] = (uint8_t) ((crc >> 8) & 0xFF);

    size_t total_size = crc_size + sizeof(uint16_t);
    return rserial_write(&serial->serial, frame, total_size) == (int) total_size;
}

void perf_emu_loop(int device_num)
{
    perf_emu_enter_critical_section();
    bool                          quit = false;
    struct perf_emu_instance_data data = pei_data[device_num];
    perf_emu_leave_critical_section();

    while (!quit)
    {
        perf_emu_enter_critical_section();
        quit = perf_emu_quit;
        data = pei_data[device_num];
        perf_emu_leave_critical_section();

        if (data.actual_mode == perf_emu_echo_mode)
        {
            // Echo mode: receive and send back
            if (rproto_get_packet(&data.serial, &data.buf, PERF_EMU_WAIT_TIMEOUT_MS))
            {
                perf_emu_add_stats(device_num, 1, 0, 0, perf_emu_packet_size(&data.buf));
                if (rproto_send_packet(&data.serial, &data.buf))
                {
                    perf_emu_add_stats(device_num, 0, 1, 0, 0);
                }
                else
                {
                    RLOG_ERROR("device %d: cannot send echo", device_num);
                }
            }
        }
        else if (data.actual_mode == perf_emu_req_resp_mode)
        {
            // Request/Response mode: respond to REQUEST with RESPONSE
            if (rproto_get_packet(&data.serial, &data.buf, PERF_EMU_WAIT_TIMEOUT_MS))
            {
                perf_emu_add_stats(device_num, 1, 0, 0, perf_emu_packet_size(&data.buf));
                if (data.buf.preamble == PREAMBLE_REQUEST)
                {
                    data.buf.preamble       = PREAMBLE_RESPONSE;
                    data.buf.payload_length = 2;
                    memcpy(data.buf.payload, "OK", 2);
                    if (rproto_send_packet(&data.serial, &data.buf))
                    {
                        perf_emu_add_stats(device_num, 0, 1, 0, 0);
                    }
                    else
                    {
                        RLOG_ERROR("device %d: cannot send response", device_num);
                    }
                }
            }
        }
        else if (data.actual_mode == perf_emu_noisy_traffic_mode)
        {
            // Noisy traffic mode: receive and respond with injected noise
            if (rproto_get_packet(&data.serial, &data.buf, PERF_EMU_WAIT_TIMEOUT_MS))
            {
                perf_emu_add_stats(device_num, 1, 0, 0, perf_emu_packet_size(&data.buf));

                // Simulate processing delay
                noisy_sleep(&data.noisy_config);

                if (perf_emu_noisy_should_drop(&data))
                {
                    // Packet lost in the noisy channel, no response is sent
                }
                else if (perf_emu_noisy_should_corrupt(&data))
                {
                    // Send a frame with corrupted CRC (raw write, rproto_send_packet
                    // would recompute the CRC)
                    if (perf_emu_send_raw_packet(&data.serial, &data.buf, true))
                    {
                        perf_emu_add_stats(device_num, 0, 1, 1, 0);
                    }
                    else
                    {
                        RLOG_ERROR("device %d: cannot send corrupted packet", device_num);
                    }
                }
                else
                {
                    if (rproto_send_packet(&data.serial, &data.buf))
                    {
                        perf_emu_add_stats(device_num, 0, 1, 0, 0);
                    }
                    else
                    {
                        RLOG_ERROR("device %d: cannot send noisy packet", device_num);
                    }
                }
            }
        }
        else if (data.actual_mode == perf_emu_unknown_mode)
        {
            usleep(1);
        }

        // Small sleep to prevent busy-waiting
        usleep(10);
    }
}

void* perf_emu_thread_loop(void* arg)
{
    int* device_num = (int*) arg;
    perf_emu_loop(*device_num);
    return NULL;
}

bool perf_emu_start(void)
{
    perf_emu_mutex_init();

    // Create socat pairs for each device
    char cmd[256];
    for (int i = 0; i < PERF_EMU_DEVICE_NUM; i++)
    {
        char port_tx[32], port_rx[32];
        snprintf(port_tx, sizeof(port_tx), "/tmp/perf_emu%d_tx", i + 1);
        snprintf(port_rx, sizeof(port_rx), "/tmp/perf_emu%d_rx", i + 1);

        // Setup and start serial
        if (rproto_serial_setup(&pei_data[i].serial, port_tx, 115200, "8N1", 0) != 0)
        {
            RLOG_ERROR("cannot setup rs emu for device %d", i);
            return false;
        }

        if (!rproto_start(&pei_data[i].serial))
        {
            RLOG_ERROR("cannot start rs emu for device %d", i);
            return false;
        }

        // Initialize results
        pei_results[i].packets_received    = 0;
        pei_results[i].packets_sent        = 0;
        pei_results[i].crc_errors_detected = 0;
        pei_results[i].bytes_transferred   = 0;

        // Start thread
        pei_data[i].device_num = i;
        if (pthread_create(&pei_data[i].emu_thread, NULL, &perf_emu_thread_loop, &pei_data[i].device_num) != 0)
        {
            RLOG_ERROR("cannot start thread emu for device %d", i);
            return false;
        }
    }

    return true;
}

void perf_emu_stop(void)
{
    perf_emu_enter_critical_section();
    perf_emu_quit = true;
    perf_emu_leave_critical_section();

    // Join all threads
    for (int i = 0; i < PERF_EMU_DEVICE_NUM; i++)
    {
        if (pthread_join(pei_data[i].emu_thread, NULL) != 0)
        {
            RLOG_ERROR("invalid stop emu thread %d", i);
        }
    }

    // Stop serial connections
    for (int i = 0; i < PERF_EMU_DEVICE_NUM; i++)
    {
        pei_data[i].actual_mode = perf_emu_unknown_mode;
        if (!rproto_stop(&pei_data[i].serial))
        {
            RLOG_ERROR("cannot stop serial %s", pei_data[i].port_name);
        }
    }

    perf_emu_quit = false;
    perf_emu_mutex_delete();
}

void perf_emu_setup_mode(int device_num, perf_emu_mode mode)
{
    if (device_num < 0 || device_num >= PERF_EMU_DEVICE_NUM)
    {
        RLOG_ERROR("Invalid device num: %d", device_num);
        return;
    }

    perf_emu_enter_critical_section();
    pei_data[device_num].actual_mode = mode;
    perf_emu_leave_critical_section();
}

void perf_emu_setup_noisy_config(int device_num, const perf_emu_noisy_config* config)
{
    if (device_num < 0 || device_num >= PERF_EMU_DEVICE_NUM)
    {
        RLOG_ERROR("Invalid device num: %d", device_num);
        return;
    }

    if (config == NULL)
    {
        RLOG_ERROR("Noisy config is NULL");
        return;
    }

    perf_emu_enter_critical_section();
    pei_data[device_num].noisy_config = *config;
    perf_emu_leave_critical_section();
}

bool perf_emu_start_traffic(int device_num)
{
    if (device_num < 0 || device_num >= PERF_EMU_DEVICE_NUM)
    {
        RLOG_ERROR("Invalid device num: %d", device_num);
        return false;
    }

    perf_emu_enter_critical_section();
    pei_data[device_num].send_client_data = true;
    perf_emu_leave_critical_section();

    return true;
}

struct perf_emu_instance_results perf_emu_get_stats(int device_num)
{
    if (device_num < 0 || device_num >= PERF_EMU_DEVICE_NUM)
    {
        RLOG_ERROR("Invalid device num: %d", device_num);
        struct perf_emu_instance_results empty = {0};
        return empty;
    }

    perf_emu_enter_critical_section();
    struct perf_emu_instance_results result = pei_results[device_num];
    perf_emu_leave_critical_section();

    return result;
}

void perf_emu_reset_stats(int device_num)
{
    if (device_num < 0 || device_num >= PERF_EMU_DEVICE_NUM)
    {
        RLOG_ERROR("Invalid device num: %d", device_num);
        return;
    }

    perf_emu_enter_critical_section();
    pei_results[device_num].packets_received    = 0;
    pei_results[device_num].packets_sent        = 0;
    pei_results[device_num].crc_errors_detected = 0;
    pei_results[device_num].bytes_transferred   = 0;
    perf_emu_leave_critical_section();
}
