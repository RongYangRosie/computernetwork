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
void forward_ip_packet(struct sr_instance *sr, uint8_t *packet, unsigned int len,
                       struct sr_if *out_iface, uint8_t *dest_mac);
int validate_packet_headers(uint8_t *packet, unsigned int len, uint16_t expected_ethertype);
void handle_arp_reply(struct sr_instance *sr, sr_arp_hdr_t *arp_hdr, struct sr_if *iface);

struct sr_if* dest_iface(struct sr_instance *sr, uint32_t source);
void send_arp_reply(struct sr_instance *sr, struct sr_if *iface, sr_arp_hdr_t *arphdr, sr_ethernet_hdr_t *ethernet_hdr);
void send_arp_request(struct sr_instance *sr, uint32_t ip);
void forward_packet(struct sr_instance *sr, uint8_t *packet, unsigned int len, struct sr_if *iface, uint8_t *dest, sr_ethernet_hdr_t *ethernet_hdr, sr_ip_hdr_t *ip_hdr);
void icmp_err(struct sr_instance *sr, uint8_t *packet, uint8_t type, uint8_t code, struct sr_if *iface, sr_ethernet_hdr_t *ethernet_hdr, sr_ip_hdr_t *ip_hdr);
void icmp_echo(struct sr_instance *sr, uint8_t *packet, unsigned int len, uint32_t dest, uint8_t type, uint8_t code, struct sr_if *iface, sr_ethernet_hdr_t *ethernet_hdr, sr_ip_hdr_t *ip_hdr, sr_icmp_hdr_t *icmp_hdr);
void handle_ip_packet(struct sr_instance *sr,
                      uint8_t *packet /* lent */,
                      unsigned int len, struct sr_if *iface);
sr_ip_hdr_t *get_ip_hdr(uint8_t *packet);
/* -- sr_if.c -- */
struct sr_if *sr_get_interface(struct sr_instance *, const char *);
struct sr_if *get_interface_from_ip(struct sr_instance*, uint32_t );
struct sr_if *get_interface_from_eth(struct sr_instance *, uint8_t *);
void sr_add_interface(struct sr_instance* , const char* );
void sr_set_ether_ip(struct sr_instance* , uint32_t );
void sr_set_ether_addr(struct sr_instance* , const unsigned char* );
void sr_print_if_list(struct sr_instance* );

#endif /* SR_ROUTER_H */
