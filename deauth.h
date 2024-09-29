#ifndef DEAUTH_H
#define DEAUTH_H

#include <pcap.h>
#include <stdint.h>

#define DEAUTH 0x00

void send_control_packet(pcap_t *handle, uint8_t *bssid, uint8_t *client);

#endif
