#ifndef DEAUTH_H
#define DEAUTH_H

#include <pcap.h>
#include <stdint.h>

#define DEAUTH 0x00


void send_control_packet(pcap_t *handle, u_char *targetAP, u_char *targetClient);

#endif
