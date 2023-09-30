#pragma once

#include "stdint.h"
#include "string.h"
#include "rserial.h"
#include "rproto_def.h"


int rproto_serial_setup(rproto_serial* instance, char* port_name, int baud, char* mode, int flowctrl);

bool rproto_serial_start(rproto_serial* instance);

bool proto_serial_get_packet(rproto_serial* instance, rproto_packet* packet, unsigned int timeout_ms);

bool proto_serial_send_packet(rproto_serial* instance, rproto_packet* packet);

bool proto_serial_stop(rproto_serial* instance);
