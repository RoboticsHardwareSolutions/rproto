#include "rproto.h"
#include "rcrc.h"
#include "rserial.h"
#include "rlog.h"
#include "rbase64.h"
#include "rtimeout.h"

bool rproto_serial_start(rproto_serial* instance)
{
    if (instance == NULL)
    {
        return false;
    }
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

bool serial_get_preamble(rproto_serial* instance, unsigned int timeout_ms)
{
    uint8_t* preamble = (uint8_t*) &instance->buf.preamble;
    int      res      = rserial_read(&instance->serial, preamble, sizeof(instance->buf.preamble), timeout_ms * 1000);
    if (res < (int) sizeof(instance->buf.preamble))
    {
        return false;
    }
    else
    {
        if (instance->buf.preamble == PREAMBLE_REQUEST || instance->buf.preamble == PREAMBLE_UNIQUE_ID ||
            instance->buf.preamble == PREAMBLE_UNIQUE_ID || instance->buf.preamble == PREAMBLE_SET_ID ||
            instance->buf.preamble == PREAMBLE_BROADCAST)
        {
            return true;
        }
        else
        {
            return false;
        }
    }
}

bool serial_get_id(rproto_serial* instance, unsigned int timeout_ms)
{
    int res = rserial_read(&instance->serial, &instance->buf.id, sizeof(instance->buf.id), timeout_ms * 1000);
    if (res < (int) sizeof(instance->buf.id))
    {
        return false;
    }
    return true;
}

bool serial_get_proto_message_length(rproto_serial* instance, unsigned int timeout_ms)
{
    int res = rserial_read(&instance->serial,
                           &instance->buf.payload_length,
                           sizeof(instance->buf.payload_length),
                           timeout_ms * 1000);

    if (res < (int) sizeof(instance->buf.payload_length))
    {
        return false;
    }

    return true;
}

bool serial_get_payload(rproto_serial* instance, unsigned int timeout_ms)
{
    int res = rserial_read(&instance->serial, instance->buf.payload, instance->buf.payload_length, timeout_ms * 1000);

    if (res < (int) instance->buf.payload_length)
    {
        return false;
    }
    return true;
}

bool serial_get_crc(rproto_serial* instance, unsigned int timeout_ms)
{
    int res =
        rserial_read(&instance->serial, (uint8_t*) &instance->buf.crc, sizeof(instance->buf.crc), timeout_ms * 1000);

    if (res < (int) sizeof(instance->buf.crc))
    {
        return false;
    }
    return true;
}

bool rproto_serial_stop(rproto_serial* instance)
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

uint16_t computing_crc_of_packet(rproto_packet* packet)
{
    size_t size =
        sizeof(packet->preamble) + sizeof(packet->id) + sizeof(packet->payload_length) + packet->payload_length;
    uint16_t result = crc16_modbus((char*) packet, (int) size);
    return result;
}

int rproto_serial_setup(rproto_serial* instance, char* port_name, int baud, char* mode, int flowctrl)
{
    if (instance == NULL || port_name == NULL || baud == 0 || mode == NULL)
    {
        return -1;
    }
    strcpy(instance->settings.port_name, port_name);
    instance->settings.baud = baud;
    strcpy(instance->settings.mode, mode);
    instance->settings.flow_ctrl = flowctrl;
    return 0;
}

bool rproto_serial_get_packet(rproto_serial* instance, rproto_packet* packet, unsigned int timeout_ms)
{
    if (instance == NULL || packet == NULL)
    {
        return false;
    }
    bool got_preamble = serial_get_preamble(instance, timeout_ms);
    if (!got_preamble)
    {
        return false;
    }

    bool got_client_id = serial_get_id(instance, timeout_ms);
    if (!got_client_id)
    {
        return false;
    }

    /** get response */
    bool got_client_id_and_length = serial_get_proto_message_length(instance, timeout_ms);
    if (!got_client_id_and_length)
    {
        return false;
    }

    bool got_proto_payload = serial_get_payload(instance, timeout_ms);
    if (!got_proto_payload)
    {
        return false;
    }

    /** get crc */
    bool got_crc = serial_get_crc(instance, timeout_ms);
    if (!got_crc)
    {
        return false;
    }

    uint16_t crc = computing_crc_of_packet(&instance->buf);

    if (instance->buf.crc != crc)
    {
        RLOG_ERROR("invalid crc ");
        return false;
    }
    memcpy(packet, &instance->buf, sizeof(packet->preamble) + sizeof(packet->id));
    encode_payload_and_copy_to(&instance->buf, packet);
    memcpy(&packet->crc, &instance->buf.crc, sizeof(packet->crc));
    return true;
}

bool rproto_serial_send_packet(rproto_serial* instance, rproto_packet* packet)
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

    uint8_t        base64_payload_packet[sizeof(rproto_packet)];
    rproto_packet* base64_packet = (rproto_packet*) base64_payload_packet;

    memcpy(base64_payload_packet, (uint8_t*) packet, sizeof(packet->preamble) + sizeof(packet->id));
    decode_payload_and_copy_to(packet, base64_packet);

    size_t size =
        sizeof(packet->preamble) + sizeof(packet->id) + sizeof(packet->payload_length) + base64_packet->payload_length;

    uint16_t* crc = (uint16_t*) &base64_payload_packet[size];
    *crc          = crc16_modbus((char*) &base64_payload_packet, (int) size);
    size += sizeof(packet->crc);
    packet->crc = *crc;

    int res = rserial_write(&instance->serial, base64_payload_packet, size);
    if (res < (int) size)
    {
        return false;
    }
    return true;
}
