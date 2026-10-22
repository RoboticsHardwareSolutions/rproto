#include <string.h>
#include <time.h>
#include <unistd.h>

#include "rproto.h"
#include "rbase64.h"
#include "rcrc.h"
#include "rlog.h"
#include "rserial.h"
#include "rtimeout.h"

// Polling granularity for rproto_get_packet()'s cumulative-deadline receive loop - matches
// the design already validated against real RS-485 hardware in
// diagnostics/rserial_layer/main.c (0-1% loss there vs. 25-75% loss through the old
// per-field rserial_read() design this replaces).
#define RPROTO_POLL_SLEEP_US 200
// rserial_read_stream() has no buffer-size parameter of its own - it always reads however
// many bytes FIONREAD reports, so this just has to be generously larger than one frame's
// ~261-byte max (it can be, since it's a one-shot stack buffer per poll, not persisted).
#define RPROTO_POLL_CHUNK_SIZE 4096
// preamble(2) + id(1) + payload_length(1); payload_length here is the base64-on-wire length.
#define RPROTO_FRAME_HEADER_LEN 4
#define RPROTO_FRAME_CRC_LEN 2

bool rproto_start(rproto_serial* instance)
{
    if (instance == NULL)
    {
        return false;
    }
    // rproto_get_packet() carries receive state (rx_queue_len) across calls, unlike the
    // old field-by-field design which had none - callers are not guaranteed to have
    // zero-initialized the instance (e.g. a plain `rproto_serial rx[3];` local array), so
    // reset it explicitly here rather than relying on that.
    instance->rx_queue_len = 0;
    if (rserial_open(&instance->serial,
                     instance->settings.port_name,
                     instance->settings.baud,
                     instance->settings.mode,
                     instance->settings.flow_ctrl,
                     RPROTO_SERIAL_BYTE_TIMEOUT_US) != 0)
    {
        RLOG_ERROR("rs serial : %s not started ", instance->settings.port_name);
        return false;
    }
#ifdef RPROTO_SERIAL_DEBUG
    RLOG_INFO("serial : %s  started ", instance->settings.port_name);
#endif
    return true;
}

static bool preamble_is_valid(uint16_t preamble)
{
    return preamble == PREAMBLE_REQUEST || preamble == PREAMBLE_RESPONSE || preamble == PREAMBLE_UNIQUE_ID ||
           preamble == PREAMBLE_SET_ID || preamble == PREAMBLE_BROADCAST;
}

static uint64_t monotonic_now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t) ts.tv_sec * 1000000000ULL + (uint64_t) ts.tv_nsec;
}

// Drops the first n bytes of the rx queue (a frame, or 2 bad preamble bytes on resync),
// sliding whatever's left down to the front so it's ready for the next call to pick up -
// nothing after byte n is ever discarded here.
static void consume_rx_queue(rproto_serial* instance, size_t n)
{
    if (n >= instance->rx_queue_len)
    {
        instance->rx_queue_len = 0;
        return;
    }
    memmove(instance->rx_queue, &instance->rx_queue[n], instance->rx_queue_len - n);
    instance->rx_queue_len -= n;
}

void encode_payload_and_copy_to(rproto_packet* src_packet, rproto_packet* dest_packet)
{
    dest_packet->payload_length =
        (uint8_t) b64_decode(src_packet->payload, src_packet->payload_length, dest_packet->payload);
}

void decode_payload_and_copy_to(rproto_packet* src_packet, rproto_packet* dest_packet)
{
    dest_packet->payload_length =
        (uint8_t) b64_encode(src_packet->payload, src_packet->payload_length, dest_packet->payload);
}

int rproto_serial_setup(rproto_serial* instance, char* port_name, int baud, char* mode, int flowctrl)
{
    if (instance == NULL || port_name == NULL || baud == 0 || mode == NULL)
    {
        return -1;
    }
    if (strlen(port_name) == 0 || strlen(mode) != 3)
    {
        return -1;
    }
    strcpy(instance->settings.port_name, port_name);
    instance->settings.baud = baud;
    strcpy(instance->settings.mode, mode);
    instance->settings.flow_ctrl = flowctrl;
    return 0;
}

// Reads one full frame off the wire against a single cumulative deadline for the whole
// frame, polling via rserial_read_stream() instead of calling rserial_read() once per field
// (preamble/id/length/payload/crc) with a fixed 500us inter-byte sub-timeout. The old
// per-field design was measured on real RS-485 hardware losing 25-75% of frames to that
// 500us sub-timeout alone, even though the bytes were still arriving - just occasionally
// slightly slower than 500us apart (transceiver turnaround, firmware jitter). This mirrors
// the design already validated there (0-1% loss) in diagnostics/rserial_layer/main.c.
bool rproto_get_packet(rproto_serial* instance, rproto_packet* packet, unsigned int timeout_ms)
{
    if (instance == NULL || packet == NULL)
    {
        return false;
    }

    uint64_t deadline_ns        = monotonic_now_ns() + (uint64_t) timeout_ms * 1000000ULL;
    bool     preamble_validated = false;

    while (true)
    {
        uint8_t* q     = instance->rx_queue;
        size_t   q_len = instance->rx_queue_len;

        if (!preamble_validated && q_len >= sizeof(uint16_t))
        {
            uint16_t preamble;
            memcpy(&preamble, &q[0], sizeof(preamble));
            if (!preamble_is_valid(preamble))
            {
                RLOG_ERROR("invalid preamble");
                consume_rx_queue(instance, sizeof(preamble));
                return false;
            }
            preamble_validated = true;
        }

        if (q_len >= RPROTO_FRAME_HEADER_LEN)
        {
            size_t expected_total = RPROTO_FRAME_HEADER_LEN + q[RPROTO_FRAME_HEADER_LEN - 1] + RPROTO_FRAME_CRC_LEN;
            if (q_len >= expected_total)
            {
                size_t   crc_offset = expected_total - RPROTO_FRAME_CRC_LEN;
                uint16_t crc_received;
                memcpy(&crc_received, &q[crc_offset], sizeof(crc_received));
                uint16_t crc_computed = crc16_ccitt((char*) q, (int) crc_offset);
                if (crc_received != crc_computed)
                {
                    RLOG_ERROR("invalid crc ");
                    consume_rx_queue(instance, expected_total);
                    return false;
                }

                // Stage the raw/base64 frame in a local rproto_packet (same packed layout
                // as the queue bytes) so encode_payload_and_copy_to() can b64_decode it,
                // then free the queue slot before touching the caller's packet - the two
                // ever alias the same memory in some callers (see requester.c), so the
                // queue must not still be holding a pointer into packet's own storage.
                rproto_packet staging = {0};
                memcpy(&staging, q, RPROTO_FRAME_HEADER_LEN);
                memcpy(staging.payload, &q[RPROTO_FRAME_HEADER_LEN], staging.payload_length);
                consume_rx_queue(instance, expected_total);

                memcpy(packet, &staging, sizeof(packet->preamble) + sizeof(packet->id));
                encode_payload_and_copy_to(&staging, packet);
                packet->crc = crc_received;
                return true;
            }
        }

        if (monotonic_now_ns() >= deadline_ns)
        {
            return false;
        }

        uint8_t chunk[RPROTO_POLL_CHUNK_SIZE];
        int     n = rserial_read_stream(&instance->serial, chunk);
        if (n > 0)
        {
            size_t room     = sizeof(instance->rx_queue) - instance->rx_queue_len;
            size_t copy_len = (size_t) n < room ? (size_t) n : room;
            memcpy(&instance->rx_queue[instance->rx_queue_len], chunk, copy_len);
            instance->rx_queue_len += copy_len;
            // Bytes beyond `room` are only ever dropped if the queue is genuinely full
            // (RPROTO_RX_QUEUE_SIZE of unconsumed backlog) - see rproto_def.h.
        }
        else if (n < 0)
        {
            return false;
        }
        else
        {
            usleep(RPROTO_POLL_SLEEP_US);
        }
    }
}

bool rproto_send_packet(rproto_serial* instance, rproto_packet* packet)
{
    if (instance == NULL || packet == NULL)
    {
        return false;
    }
    if (packet->payload_length > PROTO_MAX_PAYLOAD_LENGTH)
    {
        RLOG_ERROR("payload length is too long MAX VALUE is %d", PROTO_MAX_PAYLOAD_LENGTH);
        return false;
    }
    bool pream_correct = false;
    if (packet->preamble == PREAMBLE_REQUEST || packet->preamble == PREAMBLE_RESPONSE ||
        packet->preamble == PREAMBLE_UNIQUE_ID || packet->preamble == PREAMBLE_SET_ID ||
        packet->preamble == PREAMBLE_BROADCAST)
    {
        pream_correct = true;
    }
    else
    {
        pream_correct = false;
    }
    if (!pream_correct)
    {
        return false;
    }

    uint8_t        base64_payload_packet[sizeof(rproto_packet)];
    rproto_packet* base64_packet = (rproto_packet*) base64_payload_packet;

    memcpy(base64_payload_packet, (uint8_t*) packet, sizeof(packet->preamble) + sizeof(packet->id));
    decode_payload_and_copy_to(packet, base64_packet);

    size_t size =
        sizeof(packet->preamble) + sizeof(packet->id) + sizeof(packet->payload_length) + base64_packet->payload_length;

    uint16_t* crc = (uint16_t*) &base64_payload_packet[size];
    *crc          = crc16_ccitt((char*) &base64_payload_packet, (int) size);
    size += sizeof(packet->crc);
    packet->crc = *crc;

    int res = rserial_write(&instance->serial, base64_payload_packet, size);
    if (res < (int) size)
    {
        return false;
    }
    return true;
}

bool rproto_is_ok(rproto_serial* instance)
{
    if (instance == NULL)
    {
        return false;
    }
    return rserial_is_ok(&instance->serial);
}

bool rproto_stop(rproto_serial* instance)
{
    if (instance == NULL)
    {
        return false;
    }
#ifdef RPROTO_SERIAL_DEBUG
    RLOG_INFO(" serial : %s  stop ", instance->settings.port_name);
#endif
    return rserial_close(&instance->serial) == 0;
}
