#pragma once

#include "stdint.h"
#include "rserial.h"

#define RPROTO_SERIAL_BYTE_TIMEOUT_US 500
#define PROTO_MAX_MESSAGE_LENGTH UINT8_MAX                                 // base 64 encoded
#define PROTO_MAX_PAYLOAD_LENGTH ((PROTO_MAX_MESSAGE_LENGTH * 3 / 4) - 1)  // base64 decode length

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

typedef struct
{
    rserial               serial;
    proto_serial_settings settings;
    rproto_packet         buf;
} rproto_serial;