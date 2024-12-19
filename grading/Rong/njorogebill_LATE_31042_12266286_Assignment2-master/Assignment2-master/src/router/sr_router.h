/*-----------------------------------------------------------------------------
 * File: sr_router.h
 *
 *---------------------------------------------------------------------------*/

#ifndef SR_ROUTER_H
#define SR_ROUTER_H

#include <netinet/in.h>
#include <sys/time.h>
#include <stdio.h>

#include "sr_protocol.h"
#include "sr_arpcache.h"

/* we dont like this debug , but what to do for varargs ? */
#ifdef _DEBUG_
#define Debug(x, args...) printf(x, ## args)
#define DebugMAC(x) \
  do { int ivyl; for(ivyl=0; ivyl<5; ivyl++) printf("%02x:", \
  (unsigned char)(x[ivyl])); printf("%02x",(unsigned char)(x[5])); } while (0)
#else
#define Debug(x, args...) do{}while(0)
#define DebugMAC(x) do{}while(0)
#endif

#define INIT_TTL 255
#define PACKET_DUMP_SIZE 1024

/* forward declare */
struct sr_if;
struct sr_rt;

/* ----------------------------------------------------------------------------
 * struct sr_instance
 *
 * Encapsulation of the state for a single virtual router.
 *
 * -------------------------------------------------------------------------- */

struct sr_instance
{
    int  sockfd;   /* socket to server */
    char user[32]; /* user name */
    char host[32]; /* host name */
    char template[30]; /* template name if any */
    unsigned short topo_id;
    struct sockaddr_in sr_addr; /* address to server */
    struct sr_if* if_list; /* list of interfaces */
    struct sr_rt* routing_table; /* routing table */
    struct sr_arpcache cache;   /* ARP cache */
    pthread_attr_t attr;
    FILE* logfile;
};

/* -- sr_main.c -- */
int sr_verify_routing_table(struct sr_instance* sr);

/* -- sr_vns_comm.c -- */
int sr_send_packet(struct sr_instance* , uint8_t* , unsigned int , const char*);
int sr_connect_to_server(struct sr_instance* ,unsigned short , char* );
int sr_read_from_server(struct sr_instance* );

/* -- sr_router.c -- */
void sr_init(struct sr_instance* );
void sr_handlepacket(struct sr_instance* , uint8_t * , unsigned int , char* );

/* Add additional helper method declarations here! */
void handle_ip_packet(struct sr_instance* sr, uint8_t* packet, unsigned int len, char* interface);
void handle_arp_packet(struct sr_instance* sr, uint8_t* packet, unsigned int len, char* interface);
void handle_icmp_packet(struct sr_instance* sr, uint8_t* packet, unsigned int len, char* interface);
void arp_direct_reply(struct sr_instance* sr, uint8_t* packet, unsigned int len, uint8_t* srcAddr, uint8_t* destAddr, char* interface);
void record_packet(sr_ip_hdr_t *ipHdr, sr_icmp_hdr_t *icmpHdr);
int is_icmp_echo_reply(sr_icmp_hdr_t *icmp_hdr);

void icmp_direct_echo_reply(struct sr_instance *,
        uint8_t * /* lent */,
        unsigned int, uint8_t *,
        uint8_t *,
        char * /* lent */,
        sr_ethernet_hdr_t *,
        sr_ip_hdr_t *,
        sr_icmp_hdr_t *);
int is_icmp_echo_request(sr_icmp_hdr_t *);
void switch_route(struct sr_instance *,
        uint8_t * /* lent */,
        unsigned int,
        uint8_t *,
        uint8_t *,
        char * /* lent */,
        sr_ethernet_hdr_t *,
        sr_ip_hdr_t *,
        struct sr_rt *);



/* -- sr_if.c -- */
struct sr_if *sr_get_interface(struct sr_instance*, const char* );
struct sr_if *get_interface_from_ip(struct sr_instance*, uint32_t );
struct sr_if *get_interface_from_eth(struct sr_instance *, uint8_t *);
void sr_add_interface(struct sr_instance* , const char* );
void sr_set_ether_ip(struct sr_instance* , uint32_t );
void sr_set_ether_addr(struct sr_instance* , const unsigned char* );
void sr_print_if_list(struct sr_instance* );

#endif /* SR_ROUTER_H */