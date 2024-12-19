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
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

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

void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  printf("*** -> Received packet of length %d \n",len);

  /* fill in code here */

    struct sr_ethernet_hdr* eth_header = (struct sr_ethernet_hdr*) packet;
    uint16_t type = ethertype(packet);
    uint8_t *dst = malloc(ETHER_ADDR_LEN);
    uint8_t *src = malloc(ETHER_ADDR_LEN);
    memcpy(dst, eth_header->ether_dhost, ETHER_ADDR_LEN);
    memcpy(src, eth_header->ether_shost, ETHER_ADDR_LEN);

    //Determine if ARP or IP packet and pass packet info to helper functions
    if (type == ethertype_ip) {
        handle_ip_packets(sr, packet, interface, len, src, dst, eth_header);
    } else if (type == ethertype_arp) {
        handle_arp_packets(sr, packet, interface, len, src, dst, eth_header); 
    } else {
        fprintf(stderr, "Invalid Ether type: 0x%04x\n", ntohs(eth_header->ether_type));
    }
    //no memory leaks
    free(src);
    free(dst);
} /* end sr_handlepacket */


/* Add any additional helper methods here & don't forget to also declare
them in sr_router.h.



If you use any of these methods in sr_arpcache.c, you must also forward declare
them in sr_arpcache.h to avoid circular dependencies. Since sr_router
already imports sr_arpcache.h, sr_arpcache cannot import sr_router.h -KM */




/*
Helper funciton to handle ip packets, verifies the checksum and
*/
void handle_ip_packets(struct sr_instance* sr, uint8_t* packet,char* interface, unsigned int len, uint8_t* src_mac, uint8_t* dst_mac, struct sr_ethernet_hdr* eth_hdr) {
    //ip header memory allocation
    struct sr_ip_hdr* ip_header = (struct sr_ip_hdr*)(packet + sizeof(struct sr_ethernet_hdr));
    int ip_header_len = ip_header->ip_hl * 4;

    printf("IP Header\n");
    print_hdr_ip((uint8_t *)ip_header);

    // Verify IP checksum
    uint16_t ip_sum = ip_header->ip_sum;
    ip_header->ip_sum = 0;
    if (cksum(ip_header, ip_header_len) != ip_sum) {
        fprintf(stderr, "IP checksum failed.\n");
        return;
    }
    ip_header->ip_sum = ip_sum;
 
    //handle commands to interfaces 
    struct sr_if* iface = sr->if_list;
    int for_router = 0;

    while (iface) {
        if (ip_header->ip_dst == iface->ip) {
            for_router = 1;
            break;
        }
        iface = iface->next;
    }

    //handle command for the router
    if (for_router) {
        // Packet is for the router itself
        if (ip_header->ip_p == ip_protocol_icmp) {
            //memory allocate
            struct sr_icmp_hdr* icmp_header = 
           (struct sr_icmp_hdr*)(packet+ sizeof(struct sr_ethernet_hdr) +ip_header_len);

            int icmp_len =len-sizeof(struct sr_ethernet_hdr) - ip_header_len;

            //ICMP checksum
            uint16_t icmp_sum = icmp_header->icmp_sum;
            icmp_header->icmp_sum = 0;
            if (cksum(icmp_header, icmp_len) != icmp_sum) {
                fprintf(stderr, "ICMP checksum failed.\n");
                return;
            }
            icmp_header->icmp_sum = icmp_sum;

            if (icmp_header->icmp_type == 8) {
                //send reply, ping
                send_icmp_packet(sr, packet, interface, len, 0, 0, 1, src_mac, dst_mac);
            }
        } else {
        //handle TCP/UDP, send ICMP Port Unreachable 
        ip_header->ip_ttl--;
        if (ip_header->ip_ttl == 0) {
            //ICMP Time Exceeded
            send_icmp_packet(sr, packet, interface, len, 11, 0, 0, src_mac, dst_mac);
            return;
        }

            send_icmp_packet(sr, packet, interface, len, 3, 3, 0, src_mac, dst_mac);
        }
    } else {
        //if not for router forward it or send ip packet

        printf("Modified IP packet:\n");
        print_hdr_ip((uint8_t*)ip_header);

        send_ip_packet(sr, packet, interface, len);
    }
}



/*
To forward ip, use longest prefix match with rt, then if entry found then send the packet using 
correct info from arp entry, otherwise queue the packet 
*/
void send_ip_packet(struct sr_instance* sr, uint8_t* packet, char* interface, unsigned int len) {
    struct sr_ip_hdr* ip_header = (struct sr_ip_hdr*)(packet + sizeof(struct sr_ethernet_hdr));

    ip_header->ip_ttl--;

    if (ip_header->ip_ttl == 0) {
        //ICMP Time Exceeded
        send_icmp_packet(sr, packet, interface, len, 11, 0, 0, NULL, NULL);
        return;
    }

    else{
        ip_header->ip_sum = 0;
        ip_header->ip_sum = cksum(ip_header, sizeof(struct sr_ip_hdr));
    }



    //perform longest prefix match
    struct sr_rt* rt_match = longest_prefix_match(sr, ip_header->ip_dst);

    //handle net unreachable
    if (rt_match == NULL) {
        printf("No route, net unreachable\n");
        send_icmp_packet(sr, packet, interface, len, 3, 0, 0, NULL, NULL);
        return;
    }

    //handle ip packet
    struct sr_if* out_iface = sr_get_interface(sr, rt_match->interface);
    uint32_t next_hop_ip = rt_match->gw.s_addr;

    struct sr_arpentry* arp_entry = sr_arpcache_lookup(&sr->cache, next_hop_ip);

    if (arp_entry) {
        struct sr_ethernet_hdr* eth_header = (struct sr_ethernet_hdr*)packet;
        
        memcpy(eth_header->ether_dhost, arp_entry->mac, ETHER_ADDR_LEN);
        memcpy(eth_header->ether_shost, out_iface->addr, ETHER_ADDR_LEN);

        //Send the packet
        sr_send_packet(sr, packet, len, rt_match->interface);
        free(arp_entry);
    } else {
        //queue the packet
        struct sr_arpreq* req = sr_arpcache_queuereq(&sr->cache, next_hop_ip, packet, len, rt_match->interface);
        handle_arpreq(sr, req);
    }
}

/*
function helper implementing longest prefix match
*/
struct sr_rt* longest_prefix_match(struct sr_instance *sr, uint32_t ip_addr) {
    struct sr_rt* curr_addr = sr->routing_table;
    struct sr_rt* best_addr = NULL;
    uint32_t best_prefix = 0;

    while (curr_addr) {
        uint32_t rt_mask = curr_addr->mask.s_addr;
        uint32_t masked_ip = ip_addr & rt_mask;
        uint32_t rt_masked_ip = curr_addr->dest.s_addr & rt_mask;

        if (masked_ip == rt_masked_ip && rt_mask > best_prefix) {
            best_addr = curr_addr;
            best_prefix = rt_mask;
        }
        curr_addr = curr_addr->next;
    }

    return best_addr;
}

/*
Function to create icmp packets, handles errors messages and icmp echo replies
*/
uint8_t* create_icmp_packet(uint8_t *packet, struct sr_if *interface, unsigned int len,
unsigned int* icmp_len, uint8_t type, uint8_t err_code, int reply, uint8_t* src_mac, uint8_t* dst_mac) {
    
    uint8_t* icmp_packet;
    unsigned int packet_len;

    struct sr_ip_hdr* ip_header = (struct sr_ip_hdr*)(packet + sizeof(struct sr_ethernet_hdr));

    if (reply) {
        //ICMP echo reply, packet length is same as original
        packet_len = len;
        icmp_packet = (uint8_t*)malloc(packet_len);
        memset(icmp_packet, 0, packet_len);

        //ethernet and IP headers from original packet
        struct sr_ethernet_hdr* new_eth_header = (struct sr_ethernet_hdr*) icmp_packet;
        struct sr_ip_hdr* new_ip_header = (struct sr_ip_hdr*)(icmp_packet + sizeof(struct sr_ethernet_hdr));
        struct sr_icmp_hdr* new_icmp_header = (struct sr_icmp_hdr*)(icmp_packet + sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr));

        //Ethernet header
        memcpy(new_eth_header->ether_dhost, src_mac, ETHER_ADDR_LEN); 
        memcpy(new_eth_header->ether_shost, interface->addr, ETHER_ADDR_LEN);
        new_eth_header->ether_type = htons(ethertype_ip);

        //IP header
        new_ip_header->ip_v = 4;
        new_ip_header->ip_hl = sizeof(struct sr_ip_hdr) / 4;
        new_ip_header->ip_tos = 0;
        new_ip_header->ip_len = htons(packet_len - sizeof(struct sr_ethernet_hdr));
        new_ip_header->ip_id = htons(0);
        new_ip_header->ip_off = htons(0);
        new_ip_header->ip_ttl = 64;
        new_ip_header->ip_p = ip_protocol_icmp;
        new_ip_header->ip_src = interface->ip;
        new_ip_header->ip_dst = ip_header->ip_src;

        //recompute IP checksum
        new_ip_header->ip_sum = 0;
        new_ip_header->ip_sum = cksum(new_ip_header, sizeof(struct sr_ip_hdr));

        //ICMP header
        memcpy(new_icmp_header, packet + sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr),
               len - sizeof(struct sr_ethernet_hdr) - sizeof(struct sr_ip_hdr));
        new_icmp_header->icmp_type = type;
        new_icmp_header->icmp_code = err_code;
        new_icmp_header->icmp_sum = 0;
        new_icmp_header->icmp_sum = cksum(new_icmp_header, len - sizeof(struct sr_ethernet_hdr) - sizeof(struct sr_ip_hdr));

    } else {
        //For ICMP error messages

        //memory allocation 
        packet_len = sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr) + sizeof(struct sr_icmp_t3_hdr);
        icmp_packet = (uint8_t*)malloc(packet_len);
        memset(icmp_packet, 0, packet_len);

        struct sr_ethernet_hdr* new_eth_header = (struct sr_ethernet_hdr*) icmp_packet;
        struct sr_ip_hdr* new_ip_header = (struct sr_ip_hdr*)(icmp_packet + sizeof(struct sr_ethernet_hdr));
        struct sr_icmp_t3_hdr* new_icmp_header = (struct sr_icmp_t3_hdr*)(icmp_packet + sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr));

        //Ethernet header assignemnt
        memcpy(new_eth_header->ether_dhost, src_mac, ETHER_ADDR_LEN);
        memcpy(new_eth_header->ether_shost, interface->addr, ETHER_ADDR_LEN);
        new_eth_header->ether_type = htons(ethertype_ip);

        //IP header assigment
        new_ip_header->ip_v = 4;
        new_ip_header->ip_hl = sizeof(struct sr_ip_hdr) / 4;
        new_ip_header->ip_tos = 0;
        new_ip_header->ip_len = htons(packet_len - sizeof(struct sr_ethernet_hdr));
        new_ip_header->ip_id = htons(0);
        new_ip_header->ip_off = htons(IP_DF);
        new_ip_header->ip_ttl = 64;
        new_ip_header->ip_p = ip_protocol_icmp;
        new_ip_header->ip_src = interface->ip;
        new_ip_header->ip_dst = ip_header->ip_src;

        //Recompute IP checksum
        new_ip_header->ip_sum = 0;
        new_ip_header->ip_sum = cksum(new_ip_header, sizeof(struct sr_ip_hdr));


        //ICMP header assingment 
        new_icmp_header->icmp_type = type;
        new_icmp_header->icmp_code = err_code;
        new_icmp_header->unused = 0;
        new_icmp_header->next_mtu = 0;
        memcpy(new_icmp_header->data, ip_header, ICMP_DATA_SIZE);

        //icmp checksum recompute
        new_icmp_header->icmp_sum = 0;
        new_icmp_header->icmp_sum = cksum(new_icmp_header, sizeof(struct sr_icmp_t3_hdr));
    }

    *icmp_len = packet_len;
    return icmp_packet;
}

/*
Handles the overall sending of icmp packets, replies and messages. Based on the src mac and dst mac, 
creates create icmp packet to create packets appropiately and then sends them 
*/
void send_icmp_packet(struct sr_instance* sr, uint8_t *packet, char *interface, unsigned int len, uint8_t type,
uint8_t err_code, int reply, uint8_t* src_mac, uint8_t* dst_mac) {
    unsigned int icmp_len;
    struct sr_if* iface = sr_get_interface(sr, interface);
    struct sr_ethernet_hdr* orig_eth_hdr = (struct sr_ethernet_hdr*)packet;

    //net unreachable
    if (src_mac == NULL) {
        src_mac = orig_eth_hdr->ether_shost;
    }
    if (dst_mac == NULL) {
        dst_mac = orig_eth_hdr->ether_dhost;
    }

    uint8_t* icmp_packet = create_icmp_packet(packet, iface, len, &icmp_len, type, err_code, reply, src_mac, dst_mac);
    sr_send_packet(sr, icmp_packet, icmp_len, interface);
    free(icmp_packet);
}

/*
This helper function handles arp replies in response to requests received. Cache incoming reploesand send ip packets that are waiting on incoming Arp replies. Also removes Arp requests fromthe queue 
*/
void handle_arp_packets(struct sr_instance* sr, uint8_t* packet, char* interface, unsigned int len, uint8_t* src_mac, uint8_t* dst_mac, struct sr_ethernet_hdr* eth_hdr) {
    struct sr_arp_hdr* arp_header = (struct sr_arp_hdr*)(packet + sizeof(struct sr_ethernet_hdr));

    //verify ARP length
    if (len < sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_arp_hdr)) {
        fprintf(stderr, "invalid len for ARP\n");
        return;
    }

    if (ntohs(arp_header->ar_op) == arp_op_request) {
        printf("Received ARP request\n");
        struct sr_if* iface = sr_get_interface(sr, interface);

        if (iface && arp_header->ar_tip == iface->ip) {
            printf("Sending ARP reply\n");
            send_arp_packet(sr, packet, interface, arp_header->ar_sip, 1, src_mac, dst_mac);
        }
    } else if (ntohs(arp_header->ar_op) == arp_op_reply) {
        printf("Received ARP reply\n");
        struct sr_arpreq* req = sr_arpcache_insert(&(sr->cache), arp_header->ar_sha, arp_header->ar_sip);

        if (req) {
            // Send all packets waiting on this ARP request
            struct sr_packet* pkt;
            for (pkt = req->packets; pkt != NULL; pkt = pkt->next) {
                struct sr_ethernet_hdr* eth_hdr_pkt = (struct sr_ethernet_hdr*)pkt->buf;
                memcpy(eth_hdr_pkt->ether_shost, sr_get_interface(sr, pkt->iface)->addr, ETHER_ADDR_LEN);
                memcpy(eth_hdr_pkt->ether_dhost, arp_header->ar_sha, ETHER_ADDR_LEN);
                sr_send_packet(sr, pkt->buf, pkt->len, pkt->iface);
            }
            // remove request from queue
            sr_arpreq_destroy(&(sr->cache), req);
        }
    }
}



/*
Helper function that handles overall sending of arp packets, replies adn requests. also creates these
*/
void send_arp_packet(struct sr_instance *sr,uint8_t *packet,char *interface,uint32_t target_ip,int reply,uint8_t* src_mac, uint8_t* dst_mac) {
    struct sr_if* iface = sr_get_interface(sr, interface);
    if (!iface) {
        fprintf(stderr, "Error: Interface %s not found\n", interface);
        return;
    }

    unsigned int packet_len = sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_arp_hdr);
    uint8_t* arp_packet = (uint8_t*)malloc(packet_len);
    memset(arp_packet, 0, packet_len);

    struct sr_ethernet_hdr* new_eth_hdr = (struct sr_ethernet_hdr*)arp_packet;
    struct sr_arp_hdr* new_arp_hdr = (struct sr_arp_hdr*)(arp_packet + sizeof(struct sr_ethernet_hdr));

    if (reply) {
        //Ethernet header
        memcpy(new_eth_hdr->ether_dhost, src_mac, ETHER_ADDR_LEN);
        memcpy(new_eth_hdr->ether_shost, iface->addr, ETHER_ADDR_LEN);
        new_eth_hdr->ether_type = htons(ethertype_arp);

        //make arp header
        new_arp_hdr->ar_hrd = htons(arp_hrd_ethernet);
        new_arp_hdr->ar_pro = htons(ethertype_ip);
        new_arp_hdr->ar_hln = ETHER_ADDR_LEN;
        new_arp_hdr->ar_pln = 4;
        new_arp_hdr->ar_op = htons(arp_op_reply);
        memcpy(new_arp_hdr->ar_sha, iface->addr, ETHER_ADDR_LEN);
        new_arp_hdr->ar_sip = iface->ip;
        memcpy(new_arp_hdr->ar_tha, src_mac, ETHER_ADDR_LEN);
        new_arp_hdr->ar_tip = target_ip;

    } else {
        //Arp request
        memset(new_eth_hdr->ether_dhost, 0xff, ETHER_ADDR_LEN);
        memcpy(new_eth_hdr->ether_shost, iface->addr, ETHER_ADDR_LEN);
        new_eth_hdr->ether_type = htons(ethertype_arp);

        //Arp header
        new_arp_hdr->ar_hrd = htons(arp_hrd_ethernet);
        new_arp_hdr->ar_pro = htons(ethertype_ip);
        new_arp_hdr->ar_hln = ETHER_ADDR_LEN;
        new_arp_hdr->ar_pln = 4;
        new_arp_hdr->ar_op = htons(arp_op_request);
        memcpy(new_arp_hdr->ar_sha, iface->addr, ETHER_ADDR_LEN);
        new_arp_hdr->ar_sip = iface->ip;
        memset(new_arp_hdr->ar_tha, 0x00, ETHER_ADDR_LEN);
        new_arp_hdr->ar_tip = target_ip;
    }

    // send package
    sr_send_packet(sr, arp_packet, packet_len, interface);
    free(arp_packet);
}