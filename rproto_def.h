#pragma once

#include "stddef.h"
#include "stdint.h"
#include "rserial.h"

// No longer load-bearing for the receive path: rproto_get_packet() polls via
// rserial_read_stream() against one cumulative deadline instead of calling rserial_read()
// field-by-field, so this inter-byte timeout is never consulted there. Still passed to
// rserial_open() at rproto_start() because that call requires a non-negative value.
#define RPROTO_SERIAL_BYTE_TIMEOUT_US 500
#define PROTO_MAX_MESSAGE_LENGTH UINT8_MAX                                 // base 64 encoded
#define PROTO_MAX_PAYLOAD_LENGTH ((PROTO_MAX_MESSAGE_LENGTH * 3 / 4) - 2)  // base64 decode length

#define BROADCAST_ID 0x00

#define PREAMBLE_REQUEST 0xFFFF
#define PREAMBLE_RESPONSE 0xAAAA
#define PREAMBLE_SET_ID 0x2222
#define PREAMBLE_UNIQUE_ID 0x1111
#define PREAMBLE_BROADCAST 0x3333

#define RPROTO_SERIAL_DEBUG

#pragma pack(push)
#pragma pack(1)

typedef struct
{
    uint16_t preamble;
    uint8_t  id;
    uint8_t  payload_length;
    uint8_t  payload[PROTO_MAX_MESSAGE_LENGTH];
    uint16_t crc;
} rproto_packet;

#pragma pack(pop)

typedef struct
{
    char port_name[50];
    int  baud;
    char mode[4];
    int  flow_ctrl;
} proto_serial_settings;

// Sized well beyond one frame's ~261-byte max: rserial_read_stream() has no size cap of its
// own (it reads however many bytes FIONREAD reports), so a burst of several back-to-back
// frames (e.g. a client firing off many requests without waiting for replies, or several
// devices answering a broadcast close together) can land in the queue well ahead of
// rproto_get_packet() having consumed the earlier ones. Bytes beyond this cap are only ever
// dropped if a caller falls this far behind, which would indicate a problem upstream of
// rproto regardless.
#define RPROTO_RX_QUEUE_SIZE 4096

typedef struct
{
    rserial               serial;
    proto_serial_settings settings;
    // Bytes already pulled out of the kernel (via rserial_read_stream()) that haven't been
    // consumed into a frame yet. Persists across rproto_get_packet() calls - frames are
    // peeled off the front via memmove as they're completed, so a read that over-shoots
    // into a later frame never drops those bytes.
    uint8_t rx_queue[RPROTO_RX_QUEUE_SIZE];
    size_t  rx_queue_len;
} rproto_serial;