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

  // get the ethernet header, which is always present
  struct sr_ethernet_hdr *ethernet_header = (struct sr_ethernet_hdr *) packet;

  // check if we are dealing with ARP or IP
  if (ethertype(packet) == ethertype_arp) {

    // since we know this is ARP, we get out that header
    struct sr_arp_hdr *arp_header = (struct sr_arp_hdr *) (packet + sizeof(struct sr_ethernet_hdr));

    // drop the packet if we do not have a match with the target
    if (arp_header->ar_tip != sr_get_interface(sr, interface)->ip) return;

    // since this is ARP, it must be either a request or reply
    if (ntohs(arp_header->ar_op) == arp_op_request) {
      // this is a request, so we must reply
      reply_to_request(sr, ethernet_header, interface);
    } else {
      // this must thus be a reply, we insert into the cache so that our other code uses it later
      struct sr_arpreq *arp_original_request = sr_arpcache_insert(&sr->cache, arp_header->ar_sha, arp_header->ar_sip);

      // send out the IP packets that were waiting on this, then remove this request/packets from the queue
      send_to_all_waiting(sr, arp_original_request, arp_header);
      sr_arpreq_destroy(&sr->cache, arp_original_request);
    }
    return;
  }

  // this must be an IP packet, we get that header
  struct sr_ip_hdr *ip_header = (struct sr_ip_hdr *) ((void *) ethernet_header + sizeof(struct sr_ethernet_hdr));
  

  struct sr_if *alt_interface;
  for (alt_interface = sr->if_list; alt_interface != NULL; alt_interface = alt_interface->next) {
    if (alt_interface->ip == ip_header->ip_dst) break;
  }

  // in this case we failed to match anywhere, forward this along
  if (sr_get_interface(sr, interface)->ip != ip_header->ip_dst && alt_interface == NULL) {
    forward_ip_packet(sr, packet, len, interface);
    return;
  }

  parse_ip_packet(sr, packet, len, interface);

} /* end sr_handlepacket */

void reply_to_request (struct sr_instance *sr, struct sr_ethernet_hdr *incoming_ethernet_header, char *interface) {

  struct sr_arp_hdr *incoming_arp_header = (struct sr_arp_hdr *) ((void *) incoming_ethernet_header + sizeof(struct sr_ethernet_hdr));

  // make a new packet with space for ethernet and ARP header
  size_t arp_reply_size = sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_arp_hdr);
  uint8_t *arp_reply_packet = malloc(arp_reply_size);

  struct sr_ethernet_hdr *outgoing_ethernet_header = (struct sr_ethernet_hdr *) arp_reply_packet;
  struct sr_arp_hdr *outgoing_arp_header = (struct sr_arp_hdr *) ((void *)outgoing_ethernet_header + sizeof(struct sr_ethernet_hdr));

  // build ARP header
  outgoing_arp_header->ar_hrd = htons(arp_hrd_ethernet);
  outgoing_arp_header->ar_pro = htons(ethertype_ip);
  outgoing_arp_header->ar_hln = ETHER_ADDR_LEN;
  outgoing_arp_header->ar_pln = 4;
  outgoing_arp_header->ar_op = htons(arp_op_reply);

  struct sr_if *interface_frame = sr_get_interface(sr, interface);

  memcpy(outgoing_arp_header->ar_sha, interface_frame->addr, ETHER_ADDR_LEN);
  outgoing_arp_header->ar_sip = interface_frame->ip;

  memcpy(outgoing_arp_header->ar_tha, incoming_arp_header->ar_sha, ETHER_ADDR_LEN);
  outgoing_arp_header->ar_tip = incoming_arp_header->ar_sip;

  // build ethernet header
  memcpy(outgoing_ethernet_header->ether_dhost, incoming_ethernet_header->ether_shost, ETHER_ADDR_LEN);
  memcpy(outgoing_ethernet_header->ether_shost, interface_frame->addr, ETHER_ADDR_LEN);
  outgoing_ethernet_header->ether_type = htons(ethertype_arp);

  // ship the packet out
  sr_send_packet(sr, arp_reply_packet, arp_reply_size, interface);

  // we no longer need the packet, we can free it here
  free(arp_reply_packet);

}

void send_to_all_waiting (struct sr_instance *sr, struct sr_arpreq *arp_request, struct sr_arp_hdr *arp_header) {
  for (struct sr_packet *packet = arp_request->packets; packet != NULL; packet = packet->next) {
    // reconstruct the ethernet header for this packet
    struct sr_ethernet_hdr *ethernet_header = (struct sr_ethernet_hdr *) (packet->buf);

    // by virtue of being in the queue, we know that this is not going to be NULL
    struct sr_rt *route = route_ip_packet(sr, packet->buf);

    // get our dest to be the dest from which we got this request
    memcpy (ethernet_header->ether_dhost, arp_header->ar_sha, ETHER_ADDR_LEN);
    memcpy (ethernet_header->ether_shost, sr_get_interface(sr, route->interface)->addr, ETHER_ADDR_LEN);


    sr_send_packet(sr, packet->buf, packet->len, route->interface);
  }
}

void forward_ip_packet (struct sr_instance *sr, uint8_t *packet, unsigned int len, char *interface) {
  // get IP header
  struct sr_ip_hdr *ip_header = (struct sr_ip_hdr *) (packet + sizeof(struct sr_ethernet_hdr));
  
  if (ip_header->ip_ttl <= 1) {
    // if it is at 1 right now, it will be at zero when we decrement it - thus, this packet is dead
    send_icmp_packet(sr, packet, len, interface, 11, 0);
    return;
  }

  ip_header->ip_ttl--;
  ip_header->ip_sum = 0;
  ip_header->ip_sum = cksum(ip_header, sizeof(struct sr_ip_hdr));

  struct sr_rt *best_route = route_ip_packet(sr, packet);

  if (best_route == NULL) {
    send_icmp_packet(sr, packet, len, interface, 3, 0);
    return;
  }

  struct sr_arpentry *arp_entry = sr_arpcache_lookup(&sr->cache, ip_header->ip_dst);

  if (arp_entry != NULL) {
    send_out_ip_packet(sr, packet, len, best_route->interface, arp_entry);
    return;
  }

  // in this case, we have not found the address in the cache - let us queue the packet and send a request
  struct sr_arpreq *request = sr_arpcache_queuereq(&sr->cache, ip_header->ip_dst, packet, len, interface);
  handle_arpreq(sr, request);
}

void parse_ip_packet (struct sr_instance *sr, uint8_t *packet, unsigned int len, char *interface) {
  // get the IP header of the packet
  struct sr_ip_hdr *ip_header = (struct sr_ip_hdr *) (packet + sizeof(struct sr_ethernet_hdr));

  // firstly, check our checksum
  struct sr_ip_hdr *ip_header_duplicate = malloc(sizeof(struct sr_ip_hdr));
  memcpy(ip_header_duplicate, ip_header, sizeof(struct sr_ip_hdr));

  ip_header_duplicate->ip_sum = 0;
  ip_header_duplicate->ip_sum = cksum(ip_header_duplicate, sizeof(struct sr_ip_hdr));

  if (ip_header_duplicate->ip_sum != ip_header->ip_sum || ip_header->ip_len < 21) {
    // in this case, we have a corrupted packet - it is either too small or it has failed checksum
    free(ip_header_duplicate);
    return;
  }

  free(ip_header_duplicate);

  if (ip_header->ip_p != ip_protocol_icmp) {
    send_icmp_packet(sr, packet, len, interface, 3, 3);
    return;
  }

  // we know it is ICMP - let us get that header
  struct sr_icmp_hdr *icmp_header = (struct sr_icmp_hdr *) ((void *)ip_header + sizeof(struct sr_ip_hdr));
  
  // simply drop the packet if the request is not an echo
  if (icmp_header->icmp_type != 8) return;

  send_icmp_packet(sr, packet, len, interface, 0, 0);

}

struct sr_rt *route_ip_packet (struct sr_instance *sr, uint8_t *packet) {

  struct sr_ip_hdr *ip_header = (struct sr_ip_hdr *) (packet + sizeof(struct sr_ethernet_hdr));

  // begin routing
  struct sr_rt *best_route = NULL;
  in_addr_t best_mask = 0;

  for (struct sr_rt *route = sr->routing_table; route != NULL; route = route->next) {
    uint32_t masked_ip_dest = ip_header->ip_dst & route->mask.s_addr;
    uint32_t masked_ip_route = route->dest.s_addr & route->mask.s_addr;

    // we only care if they are equal where the mask matches, want longest such mask
    if (masked_ip_dest == masked_ip_route && route->mask.s_addr > best_mask) {
      best_route = route;
      best_mask = route->mask.s_addr;
    }
  }
  

  return best_route;
}


void send_out_ip_packet (struct sr_instance *sr, uint8_t *packet, unsigned int len, char *interface, struct sr_arpentry *arp_entry) {
  
  // make a new packet to be sent out
  uint8_t *outgoing_packet = malloc(len);
  memcpy(outgoing_packet, packet, len);

  struct sr_ethernet_hdr *outgoing_ethernet_header = (struct sr_ethernet_hdr *) outgoing_packet;

  // build ethernet header
  memcpy(outgoing_ethernet_header->ether_shost, sr_get_interface(sr, interface)->addr, ETHER_ADDR_LEN);
  memcpy(outgoing_ethernet_header->ether_dhost, arp_entry->mac, ETHER_ADDR_LEN);

  outgoing_ethernet_header->ether_type = htons(ethertype_ip);

  sr_send_packet(sr, outgoing_packet, len, interface);

  free(outgoing_packet);

  // the documentation says that this is free to be killed here
  free(arp_entry);
}

void send_icmp_packet (struct sr_instance *sr, uint8_t *packet, unsigned int len, char *interface, uint8_t type, uint8_t code) {
  // break out pieces of the old packet
  struct sr_ethernet_hdr *incoming_ethernet = (struct sr_ethernet_hdr *) packet;
  struct sr_ip_hdr *incoming_ip = (struct sr_ip_hdr *) ((void *) incoming_ethernet + sizeof(struct sr_ethernet_hdr));
  struct sr_icmp_hdr *incoming_icmp = (struct sr_icmp_hdr *) ((void *) incoming_ip + sizeof(struct sr_ip_hdr));
  
  // make a new packet with ethernet, IP, and ICMP header space
  size_t size_of_response = sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr) + sizeof(struct sr_icmp_hdr);
  // match the incoming if we are echoing
  if (type == 0) size_of_response = sizeof(struct sr_ethernet_hdr) + ntohs(incoming_ip->ip_len);

  uint8_t *response_packet = malloc(size_of_response);

  // ethernet header composes the first part of the packet
  struct sr_ethernet_hdr *response_ethernet = (struct sr_ethernet_hdr *) response_packet;

  // IP header the second part
  struct sr_ip_hdr *response_ip = (struct sr_ip_hdr *) ((void *) response_ethernet + sizeof(struct sr_ethernet_hdr));

  // ICMP header the last part
  struct sr_icmp_hdr *response_icmp = (struct sr_icmp_hdr *) ((void *) response_ip + sizeof(struct sr_ip_hdr)); 


  // for non-echo replies, we want to copy in the old header into the body
  if (type != 0) {
    memcpy(response_icmp->data, incoming_ip, sizeof(struct sr_ip_hdr));
    memcpy(response_icmp->data + sizeof(struct sr_ip_hdr), incoming_icmp, 8);
  } else {
    memcpy(response_icmp, incoming_icmp, ntohs(incoming_ip->ip_len)-sizeof(struct sr_ip_hdr));
  }

  // build ICMP to give the response we want
  response_icmp->icmp_type = type;
  response_icmp->icmp_code = code;

  response_icmp->icmp_sum = 0;
  response_icmp->icmp_sum = cksum(response_icmp, size_of_response-sizeof(struct sr_ethernet_hdr)-sizeof(struct sr_ip_hdr));

  // build IP header
  memcpy(response_ip, incoming_ip, sizeof(struct sr_ip_hdr));

  // for anything but echo replies, we set this
  if (type != 0) response_ip->ip_off = htons(IP_DF);
  
  response_ip->ip_len = htons(size_of_response - sizeof(struct sr_ethernet_hdr));

  response_ip->ip_ttl = 255;
  response_ip->ip_p = ip_protocol_icmp;
  // switch old src -> dest, since we are making a reply.
  response_ip->ip_dst = incoming_ip->ip_src;

  struct sr_if *interface_frame = sr_get_interface(sr, interface);
  response_ip->ip_src = interface_frame->ip;

  response_ip->ip_sum = 0;
  response_ip->ip_sum = cksum(response_ip, sizeof(struct sr_ip_hdr));

  // build ethernet header
  // old src -> new dest, src is interface's addr
  memcpy(response_ethernet->ether_dhost, incoming_ethernet->ether_shost, ETHER_ADDR_LEN);
  memcpy(response_ethernet->ether_shost, interface_frame->addr, ETHER_ADDR_LEN);
  response_ethernet->ether_type = htons(ethertype_ip);
  
  // packet is complete, send it off whence it came
  sr_send_packet(sr, response_packet, size_of_response, interface);

  free(response_packet);
}


/* Add any additional helper methods here & don't forget to also declare
them in sr_router.h.

If you use any of these methods in sr_arpcache.c, you must also forward declare
them in sr_arpcache.h to avoid circular dependencies. Since sr_router
already imports sr_arpcache.h, sr_arpcache cannot import sr_router.h -KM */
