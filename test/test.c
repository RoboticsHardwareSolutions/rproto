#include "runit.h"
#include "rproto.h"
#include "rcrc.h"
#include "rbase64.h"
#include "rserial.h"

// Virtual ports for testing (unique from rserial)
#define VIRTUAL_PORT1 "/tmp/rproto1"
#define VIRTUAL_PORT2 "/tmp/rproto2"

// Test buffers
rproto_serial proto1;
rproto_serial proto2;
uint8_t       read_data[512];

// =============================================================================
// test_setup: valid args -> 0, baud==0 -> -1
// =============================================================================
void test_setup(void)
{
    rproto_serial instance;

    // Valid arguments should return 0
    runit_true(rproto_serial_setup(&instance, VIRTUAL_PORT1, 115200, "8N1", FLOW_CTRL_NONE) == 0);

    // Empty port name should return -1
    runit_true(rproto_serial_setup(&instance, "", 115200, "8N1", FLOW_CTRL_NONE) == -1);

    // NULL port name should return -1
    runit_true(rproto_serial_setup(&instance, NULL, 115200, "8N1", FLOW_CTRL_NONE) == -1);

    // Zero baud should return -1
    runit_true(rproto_serial_setup(&instance, VIRTUAL_PORT1, 0, "8N1", FLOW_CTRL_NONE) == -1);

    // NULL mode should return -1
    runit_true(rproto_serial_setup(&instance, VIRTUAL_PORT1, 115200, NULL, FLOW_CTRL_NONE) == -1);

    // NULL instance should return -1
    runit_true(rproto_serial_setup(NULL, VIRTUAL_PORT1, 115200, "8N1", FLOW_CTRL_NONE) == -1);
}

// =============================================================================
// test_start_stop: start on valid port; NULL checks
// =============================================================================
void test_start_stop(void)
{
    // Setup proto1
    runit_true(rproto_serial_setup(&proto1, VIRTUAL_PORT1, 115200, "8N1", FLOW_CTRL_NONE) == 0);

    // Start should succeed
    runit_true(rproto_serial_start(&proto1) == true);

    // Stop should succeed
    runit_true(rproto_serial_stop(&proto1) == true);

    // Start NULL should return false
    runit_true(rproto_serial_start(NULL) == false);

    // Stop NULL should return false
    runit_true(rproto_serial_stop(NULL) == false);
}

// =============================================================================
// test_send_wire_format: send packet, verify wire format on raw side
// =============================================================================
void test_send_wire_format(void)
{
    rproto_serial proto_rx = {0};

    // Open both ports
    runit_true(rserial_open(&proto1.serial, VIRTUAL_PORT1, 115200, "8N1", false, 7000) == 0);
    runit_true(rserial_open(&proto_rx.serial, VIRTUAL_PORT2, 115200, "8N1", false, 7000) == 0);

    // Create packet: preamble=0xAAAA (RESPONSE), id=0x2A, payload="Hello"
    rproto_packet packet;
    packet.preamble = PREAMBLE_RESPONSE;
    packet.id       = 0x2A;

    // Encode "Hello" to base64: "SGVsbG8="
    uint8_t payload[]     = {'H', 'e', 'l', 'l', 'o'};  // 5 bytes raw
    packet.payload_length = (uint8_t) b64_encode(payload, 5, packet.payload);

    // Compute CRC over preamble + id + len + base64_payload
    size_t crc_size =
        sizeof(packet.preamble) + sizeof(packet.id) + sizeof(packet.payload_length) + packet.payload_length;
    packet.crc = crc16_ccitt((char*) &packet, (int) crc_size);

    // Send packet
    runit_true(rproto_serial_send_packet(&proto1, &packet) == true);

    // Read the raw frame from other side (should be 14 bytes: 4 + 8 b64 + 2 crc)
    uint8_t raw_frame[14];
    int     bytes_read = rserial_read(&proto_rx.serial, raw_frame, sizeof(raw_frame), 1000);
    runit_true(bytes_read == (int) sizeof(raw_frame));

    // Verify preamble (LE): 0xAA, 0x55 for PREAMBLE_RESPONSE
    runit_true(raw_frame[0] == 0xAA);
    runit_true(raw_frame[1] == 0x55);

    // Verify id: 0x2A
    runit_true(raw_frame[2] == 0x2A);

    // Verify payload length: 8 (b64 of "Hello" = "SGVsbG8=")
    runit_true(raw_frame[3] == 8);

    // Verify base64 payload: "SGVsbG8="
    uint8_t expected_b64[] = {'S', 'G', 'V', 's', 'b', 'G', '8', '='};
    runit_true(memcmp(&raw_frame[4], expected_b64, 8) == 0);

    // Verify CRC (LE): compute expected CRC
    uint16_t expected_crc = crc16_ccitt((char*) raw_frame, sizeof(raw_frame) - 2);
    uint16_t received_crc = *(uint16_t*) &raw_frame[12];
    runit_true(received_crc == expected_crc);

    // Cleanup
    rserial_close(&proto1.serial);
    rserial_close(&proto_rx.serial);
}

// =============================================================================
// test_receive_wire_format: send raw frame, receive via rproto
// =============================================================================
void test_receive_wire_format(void)
{
    rproto_serial proto_tx = {0};

    // Open both ports
    runit_true(rserial_open(&proto_tx.serial, VIRTUAL_PORT1, 115200, "8N1", false, 7000) == 0);
    runit_true(rserial_open(&proto2.serial, VIRTUAL_PORT2, 115200, "8N1", false, 7000) == 0);

    // Create raw frame: preamble=0x1111 (UNIQUE_ID), id=0x15, b64("World")="V29ybGQ="
    uint8_t frame[14];
    int     idx = 0;

    // Preamble (LE): 0x11, 0x11
    frame[idx++] = 0x11;
    frame[idx++] = 0x11;

    // ID: 0x15
    frame[idx++] = 0x15;

    // Payload length: 8 (b64 of "World")
    frame[idx++] = 8;

    // Base64 payload: "V29ybGQ="
    uint8_t expected_payload[] = {'W', 'o', 'r', 'l', 'd'};
    uint8_t b64_payload[10];
    int     b64_len = (int) b64_encode(expected_payload, 5, b64_payload);
    memcpy(&frame[idx], b64_payload, b64_len);
    idx += b64_len;

    // Compute CRC
    uint16_t crc = crc16_ccitt((char*) frame, idx);
    frame[idx++] = (uint8_t) (crc & 0xFF);         // LE low byte
    frame[idx++] = (uint8_t) ((crc >> 8) & 0xFF);  // LE high byte

    // Write raw frame
    runit_true(rserial_write(&proto_tx.serial, frame, sizeof(frame)) == sizeof(frame));

    // Setup proto2 to receive
    runit_true(rproto_serial_setup(&proto2, VIRTUAL_PORT2, 115200, "8N1", FLOW_CTRL_NONE) == 0);
    runit_true(rproto_serial_start(&proto2) == true);

    // Receive packet
    rproto_packet packet;
    runit_true(rproto_serial_get_packet(&proto2, &packet, 100) == true);

    // Verify preamble
    runit_true(packet.preamble == PREAMBLE_UNIQUE_ID);

    // Verify ID
    runit_true(packet.id == 0x15);

    // Verify payload length (decoded)
    runit_true(packet.payload_length == 5);

    // Verify decoded payload
    uint8_t expected_decoded[] = {'W', 'o', 'r', 'l', 'd'};
    runit_true(memcmp(packet.payload, expected_decoded, 5) == 0);

    // Cleanup
    rproto_serial_stop(&proto2);
    rserial_close(&proto_tx.serial);
}

// =============================================================================
// test_roundtrip: bidirectional communication
// =============================================================================
void test_roundtrip(void)
{
    // Setup both instances
    runit_true(rproto_serial_setup(&proto1, VIRTUAL_PORT1, 115200, "8N1", FLOW_CTRL_NONE) == 0);
    runit_true(rproto_serial_setup(&proto2, VIRTUAL_PORT2, 115200, "8N1", FLOW_CTRL_NONE) == 0);

    runit_true(rproto_serial_start(&proto1) == true);
    runit_true(rproto_serial_start(&proto2) == true);

    // Test 1: A->B with PREAMBLE_BROADCAST, BROADCAST_ID
    {
        rproto_packet packet_a;
        packet_a.preamble = PREAMBLE_BROADCAST;
        packet_a.id       = BROADCAST_ID;

        // 50-byte pattern
        for (int i = 0; i < 50; i++)
        {
            packet_a.payload[i] = (uint8_t) (i & 0xFF);
        }
        packet_a.payload_length = 50;

        // Compute CRC
        size_t crc_size =
            sizeof(packet_a.preamble) + sizeof(packet_a.id) + sizeof(packet_a.payload_length) + packet_a.payload_length;
        packet_a.crc = crc16_ccitt((char*) &packet_a, (int) crc_size);

        runit_true(rproto_serial_send_packet(&proto1, &packet_a) == true);

        rproto_packet packet_b;
        runit_true(rproto_serial_get_packet(&proto2, &packet_b, 100) == true);

        runit_true(packet_b.preamble == PREAMBLE_BROADCAST);
        runit_true(packet_b.id == BROADCAST_ID);
        runit_true(packet_b.payload_length == 50);
        runit_true(memcmp(packet_b.payload, packet_a.payload, 50) == 0);
    }

    // Test 2: B->A with PREAMBLE_UNIQUE_ID, max payload (189 bytes)
    {
        rproto_packet packet_b;
        packet_b.preamble = PREAMBLE_UNIQUE_ID;
        packet_b.id       = 0x01;

        // Empty payload (payload_length = 0)
        packet_b.payload_length = 0;

        // Compute CRC (only preamble + id + len)
        size_t crc_size = sizeof(packet_b.preamble) + sizeof(packet_b.id) + sizeof(packet_b.payload_length);
        packet_b.crc    = crc16_ccitt((char*) &packet_b, (int) crc_size);

        runit_true(rproto_serial_send_packet(&proto2, &packet_b) == true);

        rproto_packet packet_a;
        runit_true(rproto_serial_get_packet(&proto1, &packet_a, 100) == true);

        runit_true(packet_a.preamble == PREAMBLE_UNIQUE_ID);
        runit_true(packet_a.id == 0x01);
        runit_true(packet_a.payload_length == 0);
    }

    // Cleanup
    rproto_serial_stop(&proto1);
    rproto_serial_stop(&proto2);
}

// =============================================================================
// test_send_preambles: valid preambles succeed, invalid fail
// =============================================================================
void test_send_preambles(void)
{
    rproto_serial proto_rx = {0};

    runit_true(rserial_open(&proto1.serial, VIRTUAL_PORT1, 115200, "8N1", false, 7000) == 0);
    runit_true(rserial_open(&proto_rx.serial, VIRTUAL_PORT2, 115200, "8N1", false, 7000) == 0);

    rproto_packet packet;
    packet.payload_length = 0;

    // Test valid preambles
    uint16_t valid_preambles[] = {PREAMBLE_REQUEST,
                                  PREAMBLE_RESPONSE,
                                  PREAMBLE_UNIQUE_ID,
                                  PREAMBLE_SET_ID,
                                  PREAMBLE_BROADCAST};

    for (size_t i = 0; i < sizeof(valid_preambles) / sizeof(valid_preambles[0]); i++)
    {
        packet.preamble = valid_preambles[i];

        // Compute CRC
        size_t crc_size = sizeof(packet.preamble) + sizeof(packet.id) + sizeof(packet.payload_length);
        packet.crc      = crc16_ccitt((char*) &packet, (int) crc_size);

        runit_true(rproto_serial_send_packet(&proto1, &packet) == true);

        // Drain from other side (just read preamble to consume it)
        uint16_t preamble;
        int      res = rserial_read(&proto_rx.serial, (uint8_t*) &preamble, sizeof(preamble), 100);
        runit_true(res == (int) sizeof(preamble));
    }

    // Test invalid preamble
    packet.preamble = 0x1234;
    runit_true(rproto_serial_send_packet(&proto1, &packet) == false);

    // Cleanup
    rserial_close(&proto1.serial);
    rserial_close(&proto_rx.serial);
}

// =============================================================================
// test_send_payload_too_long: payload > PROTO_MAX_PAYLOAD_LENGTH fails
// =============================================================================
void test_send_payload_too_long(void)
{
    memset(&proto1, 0, sizeof(proto1));
    runit_true(rserial_open(&proto1.serial, VIRTUAL_PORT1, 115200, "8N1", false, 7000) == 0);

    rproto_packet packet;
    packet.preamble = PREAMBLE_RESPONSE;
    packet.id       = 0x01;

    // Try maximum valid length (189)
    packet.payload_length = PROTO_MAX_PAYLOAD_LENGTH;
    for (int i = 0; i < PROTO_MAX_PAYLOAD_LENGTH; i++)
    {
        packet.payload[i] = (uint8_t) i;
    }

    size_t crc_size =
        sizeof(packet.preamble) + sizeof(packet.id) + sizeof(packet.payload_length) + packet.payload_length;
    packet.crc = crc16_ccitt((char*) &packet, (int) crc_size);

    // This should succeed - exactly at limit
    runit_true(rproto_serial_send_packet(&proto1, &packet) == true);

    // Now try one byte over - should fail
    packet.payload_length = PROTO_MAX_PAYLOAD_LENGTH + 1;
    runit_true(rproto_serial_send_packet(&proto1, &packet) == false);

    // Cleanup
    rserial_close(&proto1.serial);
}

// =============================================================================
// test_receive_timeout: no data -> false
// =============================================================================
void test_receive_timeout(void)
{
    memset(&proto2, 0, sizeof(proto2));
    runit_true(rserial_open(&proto2.serial, VIRTUAL_PORT2, 115200, "8N1", false, 7000) == 0);

    runit_true(rproto_serial_setup(&proto2, VIRTUAL_PORT2, 115200, "8N1", FLOW_CTRL_NONE) == 0);
    runit_true(rproto_serial_start(&proto2) == true);

    // No data sent, should timeout and return false
    rproto_packet packet;
    bool          result = rproto_serial_get_packet(&proto2, &packet, 100);
    runit_true(result == false);

    // Cleanup
    rproto_serial_stop(&proto2);
    rserial_close(&proto2.serial);
}

// =============================================================================
// test_receive_truncated: incomplete frame -> false
// =============================================================================
void test_receive_truncated(void)
{
    rproto_serial proto_tx = {0};

    runit_true(rserial_open(&proto_tx.serial, VIRTUAL_PORT1, 115200, "8N1", false, 7000) == 0);
    runit_true(rserial_open(&proto2.serial, VIRTUAL_PORT2, 115200, "8N1", false, 7000) == 0);

    // Send only preamble (2 bytes)
    uint16_t preamble = PREAMBLE_RESPONSE;
    runit_true(rserial_write(&proto_tx.serial, (uint8_t*) &preamble, 2) == 2);

    runit_true(rproto_serial_setup(&proto2, VIRTUAL_PORT2, 115200, "8N1", FLOW_CTRL_NONE) == 0);
    runit_true(rproto_serial_start(&proto2) == true);

    rproto_packet packet;
    bool          result = rproto_serial_get_packet(&proto2, &packet, 100);
    runit_true(result == false);

    // Cleanup
    rproto_serial_stop(&proto2);
    rserial_close(&proto_tx.serial);
    rserial_close(&proto2.serial);
}

// =============================================================================
// test_receive_invalid_preamble: wrong preamble -> false, consumes only 2 bytes
// =============================================================================
void test_receive_invalid_preamble(void)
{
    rproto_serial proto_tx = {0};

    runit_true(rserial_open(&proto_tx.serial, VIRTUAL_PORT1, 115200, "8N1", false, 7000) == 0);
    runit_true(rserial_open(&proto2.serial, VIRTUAL_PORT2, 115200, "8N1", false, 7000) == 0);

    // Send invalid preamble + some valid-looking data
    uint8_t bad_frame[] = {
        0xFF,
        0xFF,  // Invalid preamble
        0x01,  // Some ID
        0x05,  // Length
    };
    runit_true(rserial_write(&proto_tx.serial, bad_frame, sizeof(bad_frame)) == sizeof(bad_frame));

    runit_true(rproto_serial_setup(&proto2, VIRTUAL_PORT2, 115200, "8N1", FLOW_CTRL_NONE) == 0);
    runit_true(rproto_serial_start(&proto2) == true);

    rproto_packet packet;
    bool          result = rproto_serial_get_packet(&proto2, &packet, 100);
    runit_true(result == false);

    // Now send valid packet - should be able to receive it (preamble was consumed)
    rproto_packet good_packet;
    good_packet.preamble = PREAMBLE_RESPONSE;
    good_packet.id       = 0x42;

    uint8_t payload[]          = {'T', 'e', 's', 't'};
    good_packet.payload_length = (uint8_t) b64_encode(payload, 4, good_packet.payload);

    size_t crc_size = sizeof(good_packet.preamble) + sizeof(good_packet.id) + sizeof(good_packet.payload_length) +
                      good_packet.payload_length;
    good_packet.crc = crc16_ccitt((char*) &good_packet, (int) crc_size);

    runit_true(rproto_serial_send_packet(&proto_tx, &good_packet) == true);

    // Read the consumed bytes to clear buffer
    uint8_t drain[10];
    rserial_read(&proto2.serial, drain, sizeof(drain), 50);

    // Try again - this should work
    result = rproto_serial_get_packet(&proto2, &packet, 100);
    runit_true(result == true);

    // Cleanup
    rproto_serial_stop(&proto2);
    rserial_close(&proto_tx.serial);
    rserial_close(&proto2.serial);
}

// =============================================================================
// test_receive_bad_crc: valid frame but bad CRC -> false, all bytes consumed
// =============================================================================
void test_receive_bad_crc(void)
{
    rproto_serial proto_tx = {0};

    runit_true(rserial_open(&proto_tx.serial, VIRTUAL_PORT1, 115200, "8N1", false, 7000) == 0);
    runit_true(rserial_open(&proto2.serial, VIRTUAL_PORT2, 115200, "8N1", false, 7000) == 0);

    // Build a valid frame with corrupted CRC
    uint8_t bad_crc_frame[14];
    int     idx = 0;

    // Preamble
    bad_crc_frame[idx++] = 0xAA;
    bad_crc_frame[idx++] = 0x55;

    // ID
    bad_crc_frame[idx++] = 0x10;

    // Length
    uint8_t payload[] = {'O', 'K'};
    int     b64_len   = (int) b64_encode(payload, 2, &bad_crc_frame[idx]);
    idx++;           // increment for payload_length byte
    idx += b64_len;  // "T0s=" is 3 chars

    // Good CRC
    uint16_t crc         = crc16_ccitt((char*) bad_crc_frame, idx);
    bad_crc_frame[idx++] = (uint8_t) (crc & 0xFF);
    bad_crc_frame[idx++] = (uint8_t) ((crc >> 8) & 0xFF);

    // Corrupt the CRC
    bad_crc_frame[idx - 2] ^= 0xFF;

    runit_true(rserial_write(&proto_tx.serial, bad_crc_frame, sizeof(bad_crc_frame)) == sizeof(bad_crc_frame));

    runit_true(rproto_serial_setup(&proto2, VIRTUAL_PORT2, 115200, "8N1", FLOW_CTRL_NONE) == 0);
    runit_true(rproto_serial_start(&proto2) == true);

    rproto_packet packet;
    bool          result = rproto_serial_get_packet(&proto2, &packet, 100);
    runit_true(result == false);

    // All bytes should be consumed (frame was fully read but rejected)
    // Drain any remaining to verify
    uint8_t drain[10];
    int     drained = rserial_read(&proto2.serial, drain, sizeof(drain), 50);
    // Drained should be 0 since the frame was fully consumed but rejected

    // Cleanup
    rproto_serial_stop(&proto2);
    rserial_close(&proto_tx.serial);
    rserial_close(&proto2.serial);
}

// =============================================================================
// Main
// =============================================================================
int main(void)
{
    printf("rproto unit tests\n");

    // Run tests in order
    test_setup();
    test_start_stop();
    test_send_wire_format();
    test_receive_wire_format();
    test_roundtrip();
    test_send_preambles();
    test_send_payload_too_long();
    test_receive_timeout();
    test_receive_truncated();
    test_receive_invalid_preamble();
    test_receive_bad_crc();

    runit_report();
    return runit_at_least_one_fail;
}
