/**********************************************************************
 * file:  sr_router.c
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/
#include <stdlib.h>

#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

struct sr_instance;


/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr)
{
    /* REQUIRES */
    assert(sr);

    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);

    /* Add initialization code here! */
    sr_print_if_list(sr);

} /* -- sr_init -- */

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

/* Main packet handler */
void sr_handlepacket(struct sr_instance* sr, uint8_t* packet, unsigned int len, char* interface) {
    
    if (len < sizeof(sr_ethernet_hdr_t)) {
        printf("Packet too short\n");
        return;
    }

    uint16_t ethtype = ethertype(packet);
    
    switch (ethtype) {
        case ethertype_ip:
            printf("Handling IP packet\n");
            handle_ip_packet(sr, packet, len, interface);
            break;
        case ethertype_arp:
            printf("Handling ARP packet\n");
            handle_arp_packet(sr, packet, len, interface);
            break;
        default:
            printf("Unknown packet type\n");
            break;
    }
}

void handle_ip_packet(struct sr_instance* sr, uint8_t* packet, unsigned int len, char* interface) {
    if (len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)) {
        return;
    }

    sr_ip_hdr_t* ip_hdr = (sr_ip_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));
    
    //Verify checksum
    uint16_t orig_cksum = ip_hdr->ip_sum;
    ip_hdr->ip_sum = 0;
    uint16_t computed_cksum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));
    ip_hdr->ip_sum = orig_cksum;
    
    if (orig_cksum != computed_cksum) {
        return;
    }

    //Check if packet is destined to router 
    struct sr_if* if_walker = sr->if_list;
    while (if_walker) {
        if (if_walker->ip == ip_hdr->ip_dst) {
            if (ip_hdr->ip_p == ip_protocol_icmp) {
                sr_icmp_hdr_t* icmp_hdr = (sr_icmp_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
                if (icmp_hdr->icmp_type == 8) { 
                    send_icmp_packet(sr, packet, len, 0, 0, interface); 
                }
            } else {
                send_icmp_packet(sr, packet, len, 3, 3, interface); 
            }
            return;
        }
        if_walker = if_walker->next;
    }

    //Forward packet 
    ip_hdr->ip_ttl--;
    if (ip_hdr->ip_ttl == 0) {
        send_icmp_packet(sr, packet, len, 11, 0, interface); 
        return;
    }

    //Recompute checksum 
    ip_hdr->ip_sum = 0;
    ip_hdr->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));

    //Find matching route 
    struct sr_rt* rt_entry = longest_prefix_match(sr, ip_hdr->ip_dst);
    if (!rt_entry) {
        send_icmp_packet(sr, packet, len, 3, 0, interface); 
        return;
    }

    forward_ip_packet(sr, packet, len, rt_entry);
}

/* Handle ARP packets */
void handle_arp_packet(struct sr_instance* sr, uint8_t* packet, unsigned int len, char* interface) {
    if (len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t)) {
        printf("ARP packet too short\n");
        return;
    }

    sr_arp_hdr_t* arp_hdr = (sr_arp_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));
    struct sr_if* iface = sr_get_interface(sr, interface);
    


    if (ntohs(arp_hdr->ar_op) == arp_op_request) {
        if (arp_hdr->ar_tip == iface->ip) {
            send_arp_reply(sr, packet, interface);
        }
    } else if (ntohs(arp_hdr->ar_op) == arp_op_reply) {
        struct sr_arpreq* req = sr_arpcache_insert(&(sr->cache), arp_hdr->ar_sha, arp_hdr->ar_sip);
        if (req) {
            struct sr_packet* pkt;
            for (pkt = req->packets; pkt; pkt = pkt->next) {
                forward_ip_packet(sr, pkt->buf, pkt->len, 
                    longest_prefix_match(sr, ((sr_ip_hdr_t*)(pkt->buf + sizeof(sr_ethernet_hdr_t)))->ip_dst));
            }
            sr_arpreq_destroy(&(sr->cache), req);
        }
    }
}

/* Send ICMP packet */
void send_icmp_packet(struct sr_instance* sr, uint8_t* packet, unsigned int len, uint8_t type, uint8_t code, char* interface) {
    unsigned int icmp_len;
    if (type == 0) {
        icmp_len = len;
    } else {
        icmp_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);
    }

    uint8_t* icmp_packet = (uint8_t*)malloc(icmp_len);
    sr_ethernet_hdr_t* eth_hdr = (sr_ethernet_hdr_t*)icmp_packet;
    sr_ip_hdr_t* ip_hdr = (sr_ip_hdr_t*)(icmp_packet + sizeof(sr_ethernet_hdr_t));
    
    // Set up headers 
    memcpy(eth_hdr->ether_dhost, ((sr_ethernet_hdr_t*)packet)->ether_shost, ETHER_ADDR_LEN);
    memcpy(eth_hdr->ether_shost, sr_get_interface(sr, interface)->addr, ETHER_ADDR_LEN);
    eth_hdr->ether_type = htons(ethertype_ip);

    // Set up IP header 
    ip_hdr->ip_v = 4;
    ip_hdr->ip_hl = 5;
    ip_hdr->ip_tos = 0;
    ip_hdr->ip_len = htons(icmp_len - sizeof(sr_ethernet_hdr_t));
    ip_hdr->ip_id = 0;
    ip_hdr->ip_off = htons(IP_DF);
    ip_hdr->ip_ttl = INIT_TTL;
    ip_hdr->ip_p = ip_protocol_icmp;
    ip_hdr->ip_src = sr_get_interface(sr, interface)->ip;
    ip_hdr->ip_dst = ((sr_ip_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t)))->ip_src;
    ip_hdr->ip_sum = 0;
    ip_hdr->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));

    if (type == 0) { 
        sr_icmp_hdr_t* icmp_hdr = (sr_icmp_hdr_t*)(icmp_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
        memcpy(icmp_hdr, packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t), len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t));
        icmp_hdr->icmp_type = type;
        icmp_hdr->icmp_code = code;
        icmp_hdr->icmp_sum = 0;
        icmp_hdr->icmp_sum = cksum(icmp_hdr, len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t));
    } else { 
        sr_icmp_t3_hdr_t* icmp_hdr = (sr_icmp_t3_hdr_t*)(icmp_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
        icmp_hdr->icmp_type = type;
        icmp_hdr->icmp_code = code;
        icmp_hdr->unused = 0;
        icmp_hdr->next_mtu = 0;
        memcpy(icmp_hdr->data, packet + sizeof(sr_ethernet_hdr_t), ICMP_DATA_SIZE);
        icmp_hdr->icmp_sum = 0;
        icmp_hdr->icmp_sum = cksum(icmp_hdr, sizeof(sr_icmp_t3_hdr_t));
    }

    sr_send_packet(sr, icmp_packet, icmp_len, interface);
    free(icmp_packet);
}

/* Forward IP packet */
void forward_ip_packet(struct sr_instance* sr, uint8_t* packet, unsigned int len, struct sr_rt* rt_entry) {
    if (!rt_entry) return;

    sr_ip_hdr_t* ip_hdr = (sr_ip_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));
    uint32_t next_hop_ip;
    
    if (rt_entry->gw.s_addr != 0) {
        next_hop_ip = rt_entry->gw.s_addr; 
    } else {
        next_hop_ip = ip_hdr->ip_dst;  
    }

    printf("Forwarding: dst=%u via interface %s, next_hop=%u\n", 
           ntohl(ip_hdr->ip_dst), rt_entry->interface, ntohl(next_hop_ip));

    struct sr_arpentry* arp_entry = sr_arpcache_lookup(&(sr->cache), next_hop_ip);
    if (arp_entry) {
        sr_ethernet_hdr_t* eth_hdr = (sr_ethernet_hdr_t*)packet;
        memcpy(eth_hdr->ether_dhost, arp_entry->mac, ETHER_ADDR_LEN);
        memcpy(eth_hdr->ether_shost, sr_get_interface(sr, rt_entry->interface)->addr, ETHER_ADDR_LEN);
        sr_send_packet(sr, packet, len, rt_entry->interface);
        free(arp_entry);
    } else {
        sr_arpcache_queuereq(&(sr->cache), next_hop_ip, packet, len, rt_entry->interface);
    }
}

/* Find longest prefix match in routing table */
struct sr_rt* longest_prefix_match(struct sr_instance* sr, uint32_t ip) {
    struct sr_rt* rt_walker = sr->routing_table;
    struct sr_rt* best_match = NULL;
    uint32_t longest_mask = 0;

    printf("Looking for route to IP: %u\n", ntohl(ip));

    while (rt_walker) {
        uint32_t rt_network = ntohl(rt_walker->dest.s_addr);
        uint32_t rt_mask = ntohl(rt_walker->mask.s_addr);
        uint32_t dst_ip = ntohl(ip);
        
        printf("Checking route: network=%u, mask=%u\n", rt_network, rt_mask);
        
        if ((dst_ip & rt_mask) == (rt_network & rt_mask)) {
            printf("Found matching route via %s\n", rt_walker->interface);
            if (rt_mask >= longest_mask) {
                longest_mask = rt_mask;
                best_match = rt_walker;
            }
        }
        rt_walker = rt_walker->next;
    }

    if (best_match) {
        printf("Best route found: via interface %s\n", best_match->interface);
    } else {
        printf("No route found!\n");
    }

    return best_match;
}

/* Send ARP request */
void send_arp_request(struct sr_instance* sr, uint32_t tip, char* interface) {
    unsigned int len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
    uint8_t* arp_packet = (uint8_t*)malloc(len);
    
    sr_ethernet_hdr_t* eth_hdr = (sr_ethernet_hdr_t*)arp_packet;
    sr_arp_hdr_t* arp_hdr = (sr_arp_hdr_t*)(arp_packet + sizeof(sr_ethernet_hdr_t));
    struct sr_if* iface = sr_get_interface(sr, interface);

    //Set Ethernet header 
    memset(eth_hdr->ether_dhost, 0xFF, ETHER_ADDR_LEN);
    memcpy(eth_hdr->ether_shost, iface->addr, ETHER_ADDR_LEN);
    eth_hdr->ether_type = htons(ethertype_arp);

    //Set ARP header 
    arp_hdr->ar_hrd = htons(arp_hrd_ethernet);
    arp_hdr->ar_pro = htons(ethertype_ip);
    arp_hdr->ar_hln = ETHER_ADDR_LEN;
    arp_hdr->ar_pln = 4;
    arp_hdr->ar_op = htons(arp_op_request);
    memcpy(arp_hdr->ar_sha, iface->addr, ETHER_ADDR_LEN);
    arp_hdr->ar_sip = iface->ip;
    memset(arp_hdr->ar_tha, 0, ETHER_ADDR_LEN);
    arp_hdr->ar_tip = tip;

    sr_send_packet(sr, arp_packet, len, interface);
    free(arp_packet);
}

void send_arp_reply(struct sr_instance* sr, uint8_t* packet, char* interface) {
    sr_ethernet_hdr_t* eth_hdr = (sr_ethernet_hdr_t*)packet;
    sr_arp_hdr_t* arp_hdr = (sr_arp_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));
    struct sr_if* iface = sr_get_interface(sr, interface);

    //Modify Ethernet header 
    memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, ETHER_ADDR_LEN);
    memcpy(eth_hdr->ether_shost, iface->addr, ETHER_ADDR_LEN);

    //Modify ARP header 
    arp_hdr->ar_op = htons(arp_op_reply);
    memcpy(arp_hdr->ar_tha, arp_hdr->ar_sha, ETHER_ADDR_LEN);
    memcpy(arp_hdr->ar_sha, iface->addr, ETHER_ADDR_LEN);
    uint32_t temp_ip = arp_hdr->ar_tip;
    arp_hdr->ar_tip = arp_hdr->ar_sip;
    arp_hdr->ar_sip = temp_ip;

    sr_send_packet(sr, packet, sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t), interface);
}




/* Add any additional helper methods here & don't forget to also declare
them in sr_router.h.

If you use any of these methods in sr_arpcache.c, you must also forward declare
them in sr_arpcache.h to avoid circular dependencies. Since sr_router
already imports sr_arpcache.h, sr_arpcache cannot import sr_router.h -KM */
