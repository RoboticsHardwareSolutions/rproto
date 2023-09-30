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
                     SERIAL_BYTE_TIMEOUT_US) != 0)
    {
        RLOG_ERROR("rs serial : %s not started ", instance->settings.port_name);
        return false;
    }
#ifdef RADIO_SERIAL_DEBUG
    RLOG_INFO("radio serial : %s  started ", instance->settings.port_name);
#endif
    instance->state = rproto_serial_idle;
    return true;
}

bool radio_serial_get_preamble(rproto_serial* instance, unsigned int timeout_ms)
{
    if (instance->state != rproto_serial_idle)
    {
        RLOG_ERROR("rs serial invalid state for get preamble");
        return false;
    }
    instance->state = rproto_serial_wait_preamble;
    int       result;
    bool      resp_req  = false;
    bool      unique_id = false;
    bool      broadcast = false;
    uint8_t*  preamble  = (uint8_t*) &instance->buf.preamble;
    rt timeout_get_preamble;

    if (rt_set(&timeout_get_preamble, timeout_ms * 1000) != 0)
    {
        RLOG_ERROR("Radio serial cannot set timeout");
        instance->state = rproto_serial_idle;
        return false;
    }

    do
    {
        /** timeout */
        int time_res = rt_timed_out(&timeout_get_preamble);
        if (time_res == -1)
        {
            RLOG_ERROR("rs serial get preamble  error set timout  ");
            instance->state = rproto_serial_idle;
            return false;
        }
        else if (time_res == 1)
        {
#ifdef RADIO_SERIAL_DEBUG
            RLOG_WARNING("radio serial get preamble timeout ");
#endif
            instance->state = rproto_serial_idle;
            return false;
        }

        /** first byte */
        result = rserial_read(&instance->serial, preamble, 1, timeout_ms * 1000);
        if (result == -1)
        {
#ifdef RADIO_SERIAL_DEBUG
            RLOG_INFO("Radio serial cannot got preamble");
#endif
            instance->state = rproto_serial_idle;
            return false;
        }
        else if (result == 1)
        {
            // FIXME this is trash )
            if ((preamble[0] << 8 | preamble[0]) == PREAMBLE_RESPONSE ||
                (preamble[0] << 8 | preamble[0]) == PREAMBLE_REQUEST)
            {
                resp_req = true;
            }
            else if ((preamble[0] << 8 | preamble[0]) == PREAMBLE_UNIQUE_ID ||
                     (preamble[0] << 8 | preamble[0]) == PREAMBLE_SET_ID)
            {
                unique_id = true;
            }
            else if ((preamble[0] << 8 | preamble[0]) == PREAMBLE_BROADCAST)
            {
                broadcast = true;
            }
            else
            {
#ifdef RADIO_SERIAL_DEBUG
                RLOG_WARNING("Read byte will drop");
#endif
                continue;
            }
        }

        /** second byte */
        result = rserial_read(&instance->serial, &preamble[1], 1, timeout_ms * 100);
        if (result == -1)
        {
#ifdef RADIO_SERIAL_DEBUG
            RLOG_INFO("Radio cannot got second byte error");
#endif
            instance->state = rproto_serial_idle;
            return false;
        }
        else if (result == 1)
        {
            // FIXME this is trash )
            if (resp_req && ((preamble[1] << 8 | preamble[0]) == PREAMBLE_RESPONSE ||
                             (preamble[1] << 8 | preamble[0]) == PREAMBLE_REQUEST))
            {
                instance->state = rproto_serial_wait_client_id_and_length;
                return true;
            }
            else if (unique_id && ((preamble[1] << 8 | preamble[0]) == PREAMBLE_UNIQUE_ID ||
                                   (preamble[1] << 8 | preamble[0]) == PREAMBLE_SET_ID))
            {
                instance->state = rproto_serial_wait_client_id_and_length;
                return true;
            }
            else if (broadcast && ((preamble[1] << 8 | preamble[0]) == PREAMBLE_BROADCAST))
            {
                instance->state = rproto_serial_wait_client_id_and_length;
                return true;
            }
            else
            {
                resp_req = unique_id = broadcast = false;
                continue;
            }
        }

    } while (1);
}

bool radio_serial_get_id(rproto_serial* instance, unsigned int timeout_ms)
{
    if (instance->state != rproto_serial_wait_client_id_and_length)
    {
        RLOG_ERROR("rs serial invalid state for get client id and length");
        return false;
    }

    int res = rserial_read(&instance->serial, &instance->buf.id, sizeof(instance->buf.id), timeout_ms * 1000);

    if ((size_t) res < sizeof(instance->buf.id))
    {
        instance->state = rproto_serial_idle;
        return false;
    }
    return true;
}

bool radio_get_proto_message_length(rproto_serial* instance, unsigned int timeout_ms)
{
    if (instance->state != rproto_serial_wait_client_id_and_length)
    {
        RLOG_ERROR("rs serial invalid state for get  length");
        return false;
    }
    int res = rserial_read(&instance->serial,
                           &instance->buf.payload_length,
                           sizeof(instance->buf.payload_length),
                           timeout_ms * 1000);

    if (res < (int) sizeof(instance->buf.payload_length))
    {
        instance->state = rproto_serial_idle;
        return false;
    }
    instance->state = rproto_serial_wait_proto_payload;
    return true;
}

bool radio_serial_get_payload(rproto_serial* instance, unsigned int timeout_ms)
{
    if (instance->state != rproto_serial_wait_proto_payload)
    {
        RLOG_ERROR("rs serial invalid state for get proto payload");
        return false;
    }

    int res = rserial_read(&instance->serial, instance->buf.payload, instance->buf.payload_length, timeout_ms * 1000);

    if (res < instance->buf.payload_length)
    {
        instance->state = rproto_serial_idle;
        return false;
    }
    instance->state = rproto_serial_wait_crc;
    return true;
}

bool radio_serial_get_crc(rproto_serial* instance, unsigned int timeout_ms)
{
    if (instance->state != rproto_serial_wait_crc)
    {
        RLOG_ERROR("rs serial invalid state for get crc");
        return false;
    }
    int res =
        rserial_read(&instance->serial, (uint8_t*) &instance->buf.crc, sizeof(instance->buf.crc), timeout_ms * 1000);
    instance->state = rproto_serial_idle;
    if (res < (int) sizeof(instance->buf.crc))
    {
        return false;
    }
    return true;
}

bool proto_serial_stop(rproto_serial* instance)
{
    if (instance == NULL)
    {
        return false;
    }
#ifdef RADIO_SERIAL_DEBUG
    RLOG_INFO("radio serial : %s  stop ", instance->settings.port_name);
#endif
    return rserial_close(&instance->serial) == 0;
}

void radio_encode_payload_and_copy_to(rproto_packet* src_packet, rproto_packet* dest_packet)
{
    dest_packet->payload_length =
        (uint8_t) b64_decode(src_packet->payload, src_packet->payload_length, dest_packet->payload);
}

void radio_decode_payload_and_copy_to(rproto_packet* src_packet, rproto_packet* dest_packet)
{
    dest_packet->payload_length =
        (uint8_t) b64_encode(src_packet->payload, src_packet->payload_length, dest_packet->payload);
}

uint16_t radio_computing_crc_of_packet(rproto_packet* packet)
{
    size_t size =
        sizeof(packet->preamble) + sizeof(packet->id) + sizeof(packet->payload_length) + packet->payload_length;

    uint16_t result = crc16((char*) packet, (int) size);

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

bool proto_serial_get_packet(rproto_serial* instance, rproto_packet* packet, unsigned int timeout_ms)
{
    if (instance == NULL || packet == NULL)
    {
        return false;
    }
    bool got_preamble = radio_serial_get_preamble(instance, timeout_ms);
    if (!got_preamble)
    {
        return false;
    }

    bool got_client_id = radio_serial_get_id(instance, timeout_ms / 10);
    if (!got_client_id)
    {
        return false;
    }

    /** get response */
    bool got_client_id_and_length = radio_get_proto_message_length(instance, timeout_ms / 10);
    if (!got_client_id_and_length)
    {
        return false;
    }

    bool got_proto_payload = radio_serial_get_payload(instance, timeout_ms / 2);
    if (!got_proto_payload)
    {
        return false;
    }

    /** get crc */
    bool got_crc = radio_serial_get_crc(instance, timeout_ms / 10);
    if (!got_crc)
    {
        return false;
    }

    uint16_t crc = radio_computing_crc_of_packet(&instance->buf);

    if (instance->buf.crc != crc)
    {
        RLOG_ERROR("rs invalid crc ");
        return false;
    }
    memcpy(packet, &instance->buf, sizeof(packet->preamble) + sizeof(packet->id));
    radio_encode_payload_and_copy_to(&instance->buf, packet);
    memcpy(&packet->crc, &instance->buf.crc, sizeof(packet->crc));
    return true;
}

bool proto_serial_send_packet(rproto_serial* instance, rproto_packet* packet)
{
    if (instance == NULL || packet == NULL)
    {
        return false;
    }
    if (packet->payload_length > MAX_PAYLOAD_LENGTH)
    {
        RLOG_ERROR("payload length is too long MAX VALUE is %d", MAX_PAYLOAD_LENGTH);
        return false;
    }

    if (instance->state != rproto_serial_idle)
    {
        RLOG_ERROR("rs serial invalid state for send packet ");
        return false;
    }

    uint8_t       base64_payload_packet[sizeof(rproto_packet)];
    rproto_packet* base64_radio_packet = (rproto_packet*) base64_payload_packet;

    memcpy(base64_payload_packet, (uint8_t*) packet, sizeof(packet->preamble) + sizeof(packet->id));
    radio_decode_payload_and_copy_to(packet, base64_radio_packet);

    size_t size = sizeof(packet->preamble) + sizeof(packet->id) + sizeof(packet->payload_length) +
                  base64_radio_packet->payload_length;

    uint16_t* crc = (uint16_t*) &base64_payload_packet[size];
    *crc          = crc16((char*) &base64_payload_packet, (int) size);
    size += sizeof(packet->crc);
    packet->crc = *crc;

    int res = rserial_write(&instance->serial, base64_payload_packet, size);
    if (res < (int) size)
    {
        return false;
    }
    return true;
}
