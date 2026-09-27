#include "perf_emu.h"
#include "rproto.h"
#include "rcrc.h"
#include "rbase64.h"
#include "runit.h"
#include "time.h"
#include "unistd.h"
#include "stdlib.h"
#include "string.h"

// Test ports
#define TEST_PORT_TX "/tmp/perf_emu1_tx"
#define TEST_PORT_RX "/tmp/perf_emu1_rx"

// Random noise generator state
static uint32_t xorshift_state = 12345;

// Simple XORSHIFT random number generator
static uint32_t xorshift32(void)
{
    uint32_t x = xorshift_state;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    xorshift_state = x;
    return x;
}

// Global results storage
static perf_test_results g_throughput_results = {0};
static perf_test_results g_latency_results    = {0};

// Helper to create a valid rproto packet
static bool create_valid_packet(rproto_packet* pkt,
                                uint16_t       preamble,
                                uint8_t        id,
                                const uint8_t* payload,
                                size_t         payload_len)
{
    if (payload_len > PROTO_MAX_PAYLOAD_LENGTH)
    {
        printf("ERROR: Payload too long: %zu\n", payload_len);
        return false;
    }

    pkt->preamble       = preamble;
    pkt->id             = id;
    pkt->payload_length = (uint8_t) payload_len;

    // Copy raw payload (rproto will encode to base64 internally)
    memcpy(pkt->payload, payload, payload_len);

    // Compute CRC over raw data (preamble + id + len + payload)
    size_t crc_size = sizeof(pkt->preamble) + sizeof(pkt->id) + sizeof(pkt->payload_length) + payload_len;
    pkt->crc        = crc16_ccitt((char*) pkt, (int) crc_size);

    return true;
}

// Helper to send a packet and measure time
static uint64_t send_packet_with_timestamp(rproto_serial* tx, rproto_packet* pkt)
{
    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);

    bool result = rproto_send_packet(tx, pkt);

    clock_gettime(CLOCK_MONOTONIC, &end);
    uint64_t elapsed_us = (end.tv_sec - start.tv_sec) * 1000000 + (end.tv_nsec - start.tv_nsec) / 1000;

    return result ? elapsed_us : 0;
}

// Test 1: Throughput test - measure maximum data rate
void test_throughput(void)
{
    printf("\n=== Throughput Test ===\n");

    rproto_serial proto_rx = {0};

    // Setup transmitter on TX port
    runit_true(rproto_serial_setup(&proto_rx, TEST_PORT_RX, 115200, "8N1", 0) == 0);
    runit_true(rproto_start(&proto_rx));

    // Setup emulator in echo mode for throughput
    perf_emu_setup_mode(0, perf_emu_echo_mode);

    // Test parameters
    const int    NUM_PACKETS  = 100;
    const size_t PAYLOAD_SIZE = 50;  // bytes (raw, not base64)
    uint8_t      payload[PAYLOAD_SIZE];
    memset((void*) payload, 0xAA, PAYLOAD_SIZE);

    // Create packet template
    rproto_packet pkt;
    create_valid_packet(&pkt, PREAMBLE_REQUEST, 0x01, payload, PAYLOAD_SIZE);

    // Send packets and measure time
    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);

    for (int i = 0; i < NUM_PACKETS; i++)
    {
        // Send packet
        runit_true(rproto_send_packet(&proto_rx, &pkt));

        // Receive echo (with timeout)
        rproto_packet rx_pkt;
        bool          got = rproto_get_packet(&proto_rx, &rx_pkt, 100);
        runit_true(got);

        // Verify it's a response
        runit_true(rx_pkt.preamble == PREAMBLE_REQUEST);
    }

    clock_gettime(CLOCK_MONOTONIC, &end);

    // Calculate throughput
    uint64_t total_bytes     = NUM_PACKETS * (sizeof(pkt.preamble) + sizeof(pkt.id) + sizeof(pkt.payload_length) +
                                              PAYLOAD_SIZE + sizeof(pkt.crc));
    uint64_t elapsed_us      = (end.tv_sec - start.tv_sec) * 1000000 + (end.tv_nsec - start.tv_nsec) / 1000;
    double   elapsed_sec     = (double) elapsed_us / 1000000.0;
    double   throughput_kbps = (total_bytes / 1024.0) / elapsed_sec;

    printf("Sent: %d packets, %zu bytes each\n", NUM_PACKETS, PAYLOAD_SIZE);
    printf("Elapsed: %.3f seconds\n", elapsed_sec);
    printf("Throughput: %.2f KB/s\n", throughput_kbps);
    printf("Effective bitrate: %.2f kbps\n", throughput_kbps * 8);

    // Store result
    g_throughput_results.throughput_kbps = throughput_kbps;

    // Cleanup
    runit_true(rproto_stop(&proto_rx));

    // Reset stats
    perf_emu_reset_stats(0);
}

// Test 2: Latency test - measure packet round-trip time
void test_latency(void)
{
    printf("\n=== Latency Test ===\n");

    rproto_serial proto_rx = {0};
    // Setup
    runit_true(rproto_serial_setup(&proto_rx, TEST_PORT_RX, 115200, "8N1", 0) == 0);
    runit_true(rproto_start(&proto_rx));

    // Setup emulator in echo mode for latency measurement
    perf_emu_setup_mode(0, perf_emu_echo_mode);

    // Test parameters
    const int    NUM_SAMPLES = 100;
    uint64_t     latencies[NUM_SAMPLES];
    const size_t PAYLOAD_SIZE = 10;
    uint8_t      payload[PAYLOAD_SIZE];
    memset((void*) payload, 0xBB, PAYLOAD_SIZE);

    rproto_packet pkt;
    create_valid_packet(&pkt, PREAMBLE_REQUEST, 0x02, payload, PAYLOAD_SIZE);

    // Measure latencies
    for (int i = 0; i < NUM_SAMPLES; i++)
    {
        struct timespec start, end;
        clock_gettime(CLOCK_MONOTONIC, &start);

        runit_true(rproto_send_packet(&proto_rx, &pkt));

        rproto_packet rx_pkt;
        bool          got = rproto_get_packet(&proto_rx, &rx_pkt, 100);
        runit_true(got);

        clock_gettime(CLOCK_MONOTONIC, &end);

        latencies[i] = (end.tv_sec - start.tv_sec) * 1000000 + (end.tv_nsec - start.tv_nsec) / 1000;
    }

    // Calculate statistics
    uint64_t sum = 0, min = UINT64_MAX, max = 0;
    for (int i = 0; i < NUM_SAMPLES; i++)
    {
        sum += latencies[i];
        if (latencies[i] < min)
            min = latencies[i];
        if (latencies[i] > max)
            max = latencies[i];
    }

    double avg = (double) sum / NUM_SAMPLES;

    printf("Samples: %d\n", NUM_SAMPLES);
    printf("Latency avg: %.2f us\n", avg);
    printf("Latency min: %lu us\n", (unsigned long) min);
    printf("Latency max: %lu us\n", (unsigned long) max);

    // Store result
    g_latency_results.latency_avg_us = avg;
    g_latency_results.latency_min_us = (double) min;
    g_latency_results.latency_max_us = (double) max;

    // Cleanup
    runit_true(rproto_stop(&proto_rx));

    // Reset stats
    perf_emu_reset_stats(0);
}

// Test 3: Concurrent channels test
void test_concurrent_channels(void)
{
    printf("\n=== Concurrent Channels Test ===\n");

    // Setup 3 parallel channels
    rproto_serial rx[3];
    const char*   port_names[] = {"/tmp/perf_emu1_rx", "/tmp/perf_emu2_rx", "/tmp/perf_emu3_rx"};

    // Setup all ports
    for (int i = 0; i < 3; i++)
    {
        runit_true(rproto_serial_setup(&rx[i], (char*) port_names[i], 115200, "8N1", 0) == 0);
        runit_true(rproto_start(&rx[i]));
    }

    // Setup emulators in echo mode
    for (int i = 0; i < 3; i++)
    {
        perf_emu_setup_mode(i, perf_emu_req_resp_mode);
    }

    // Send packets on all channels simultaneously
    const int    NUM_PACKETS_PER_CHANNEL = 20;
    const size_t PAYLOAD_SIZE            = 30;
    uint8_t      payload[PAYLOAD_SIZE];
    memset((void*) payload, 0xDD + getpid(), PAYLOAD_SIZE);

    rproto_packet pkt;
    create_valid_packet(&pkt, PREAMBLE_REQUEST, 0x10, payload, PAYLOAD_SIZE);

    // Send on all channels
    for (int c = 0; c < 3; c++)
    {
        for (int i = 0; i < NUM_PACKETS_PER_CHANNEL; i++)
        {
            runit_true(rproto_send_packet(&rx[c], &pkt));
        }
    }

    // Receive from all channels
    for (int c = 0; c < 3; c++)
    {
        int received = 0;
        for (int i = 0; i < NUM_PACKETS_PER_CHANNEL; i++)
        {
            rproto_packet rx_pkt;
            bool          got = rproto_get_packet(&rx[c], &rx_pkt, 100);
            if (got && rx_pkt.preamble == PREAMBLE_RESPONSE)
            {
                received++;
            }
        }
        printf("Channel %d: sent %d, received %d\n", c + 1, NUM_PACKETS_PER_CHANNEL, received);
    }

    // Verify all emulators processed packets
    for (int i = 0; i < 3; i++)
    {
        struct perf_emu_instance_results stats = perf_emu_get_stats(i);
        printf("Emulator %d processed: %lu packets\n", i + 1, (unsigned long) stats.packets_received);
    }

    // Cleanup
    for (int i = 0; i < 3; i++)
    {
        runit_true(rproto_stop(&rx[i]));
    }

    // Reset stats
    for (int i = 0; i < 3; i++)
    {
        perf_emu_reset_stats(i);
    }
}

// Test 4: Noisy traffic test - verify packet loss and CRC error injection
void test_noisy_traffic(void)
{
    printf("\n=== Noisy Traffic Test ===\n");

    rproto_serial proto_rx = {0};
    runit_true(rproto_serial_setup(&proto_rx, TEST_PORT_RX, 115200, "8N1", 0) == 0);
    runit_true(rproto_start(&proto_rx));

    // Setup emulator in noisy mode: 50% packet loss, 50% CRC errors
    perf_emu_setup_mode(0, perf_emu_noisy_traffic_mode);
    perf_emu_noisy_config noisy_cfg = {
        .packet_loss_percent = 50.0,
        .crc_error_percent   = 50.0,
        .min_delay_ms        = 0,
        .max_delay_ms        = 1,
    };
    perf_emu_setup_noisy_config(0, &noisy_cfg);

    const int    NUM_PACKETS  = 100;
    const size_t PAYLOAD_SIZE = 20;
    uint8_t      payload[PAYLOAD_SIZE];
    memset((void*) payload, 0xCC, PAYLOAD_SIZE);

    rproto_packet pkt;
    create_valid_packet(&pkt, PREAMBLE_REQUEST, 0x03, payload, PAYLOAD_SIZE);

    int valid_responses = 0;
    for (int i = 0; i < NUM_PACKETS; i++)
    {
        runit_true(rproto_send_packet(&proto_rx, &pkt));

        // Dropped packets time out, corrupted ones are rejected by CRC check
        rproto_packet rx_pkt;
        bool          got = rproto_get_packet(&proto_rx, &rx_pkt, 50);
        if (got && rx_pkt.preamble == PREAMBLE_REQUEST)
        {
            valid_responses++;
        }
    }

    struct perf_emu_instance_results stats = perf_emu_get_stats(0);
    printf("Sent: %d packets\n", NUM_PACKETS);
    printf("Valid responses received: %d\n", valid_responses);
    printf("Emulator stats: received=%lu sent=%lu crc_errors=%lu bytes=%lu\n",
           (unsigned long) stats.packets_received,
           (unsigned long) stats.packets_sent,
           (unsigned long) stats.crc_errors_detected,
           (unsigned long) stats.bytes_transferred);

    // The emulator must have received every packet we sent
    runit_true(stats.packets_received == (uint64_t) NUM_PACKETS);
    // Packet loss must have dropped some responses
    runit_true(stats.packets_sent < (uint64_t) NUM_PACKETS);
    // Some responses must have been sent with corrupted CRC
    runit_true(stats.crc_errors_detected > 0);
    // And some valid responses must have gotten through
    runit_true(valid_responses > 0);

    // Cleanup
    runit_true(rproto_stop(&proto_rx));
    perf_emu_reset_stats(0);
}

// Print summary of all tests
static void print_test_summary(void)
{
    printf("\n=== Performance Test Summary ===\n");
    printf("Run these tests to measure rproto performance:\n");
    if (g_throughput_results.throughput_kbps > 0)
    {
        printf("  - Throughput:   %.2f KB/s\n", g_throughput_results.throughput_kbps);
    }
    if (g_latency_results.latency_avg_us > 0)
    {
        printf("  - Latency avg:  %.2f us\n", g_latency_results.latency_avg_us);
        printf("  - Latency min:  %.2f us\n", g_latency_results.latency_min_us);
        printf("  - Latency max:  %.2f us\n", g_latency_results.latency_max_us);
    }
}

// Entry point for all performance tests (called from test.c)
void run_perf_tests(void)
{
    printf("rproto Performance Tests\n");
    printf("========================\n");

    // Initialize random seed
    xorshift_state = (uint32_t) time(NULL);

    // Start emulator
    if (!perf_emu_start())
    {
        printf("Failed to start performance emulator\n");
        runit_fail();
        return;
    }

    // Run tests
    test_throughput();
    test_latency();
    test_concurrent_channels();
    test_noisy_traffic();
    print_test_summary();

    perf_emu_stop();

    printf("\n=== Perf Tests Complete ===\n");
}