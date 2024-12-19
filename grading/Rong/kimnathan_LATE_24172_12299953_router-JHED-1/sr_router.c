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

void sr_init(struct sr_instance *sr)
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

void sr_handlepacket(struct sr_instance *sr,
                     uint8_t *packet /* lent */,
                     unsigned int len,
                     char *interface /* lent */)
{
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  printf("*** -> Received packet of length %d \n", len);

  /* fill in code here */
  uint16_t packet_type = ethertype(packet);
  print_hdrs(packet, len);
  if (packet_type == ethertype_arp)
  {
    sr_arp_hdr_t *arp_pkt = (sr_arp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
    uint16_t opcode = ntohs(arp_pkt->ar_op);
    if (opcode == arp_op_request)
    { // it's a request
      printf("Received ARP request\n");
      sr_handle_arprequest(sr, arp_pkt, len, interface, packet);
    }
    else if (opcode == arp_op_reply)
    {
      printf("Received ARP reply\n");
      sr_handle_arpreply(sr, arp_pkt, len, interface);
    }
    else
    {
      fprintf(stderr, "Received invalid ARP packet opcode\n");
    }
  }
  else if (packet_type == ethertype_ip)
  {
    // grab it's IP header
    sr_ip_hdr_t *req_ip_hdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
    //printf("IP Packet of length %d was received.\n", len);
    //print_hdr_ip((uint8_t *)req_ip_hdr);

    // verify checksum
    uint16_t ip_checksum = req_ip_hdr->ip_sum;
    req_ip_hdr->ip_sum = 0;
    req_ip_hdr->ip_sum = cksum(req_ip_hdr, sizeof(sr_ip_hdr_t));

    if (req_ip_hdr->ip_sum != ip_checksum)
    {
      fprintf(stderr, "Received an IP packet with invalid checksum\n");
      return;
    }

    // Check if IP packet meets min length
    if (len - sizeof(sr_ethernet_hdr_t) < sizeof(sr_ip_hdr_t))
    {
      fprintf(stderr, "Received an IP packet that's too small!!!\n");
      return;
    }

    // check if ip packet meets minimum length
    // determine if ip packet is destined for router
    struct sr_if *router_if = get_interface_from_ip(sr, req_ip_hdr->ip_dst);
    if (router_if)
    {
      printf("Received IP packet destined for router!!!\n");
      // sr_ip_hdr_t *req_ip_hdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t)); comment out since it was already done earlier above
      sr_icmp_hdr_t *req_icmp_hdr = (sr_icmp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
      struct sr_if *outgoing_iface = router_if; 
      if (req_ip_hdr->ip_p != ip_protocol_icmp)
      {
        printf( "Received IP packet not ICMP, Type 3 Code 3\n");
        sr_destined_for_router(sr, packet, len, interface, outgoing_iface, 0);
      }
      if (req_icmp_hdr->icmp_type == 8)
      { 
        printf("Received ICMP echo request, preparing to echo!!!\n");
        sr_destined_for_router(sr, packet, len, interface, outgoing_iface, 1);
      }     
    }
    else
    {
      fprintf(stdout, "Forwarding!!!\n");
      sr_handle_ip_forwarding(sr, packet, len, interface);
    }
  }

} /* end sr_handlepacket */

/* Add any additional helper methods here & don't forget to also declare
them in sr_router.h.

If you use any of these methods in sr_arpcache.c, you must also forward declare
them in sr_arpcache.h to avoid circular dependencies. Since sr_router
already imports sr_arpcache.h, sr_arpcache cannot import sr_router.h -KM */

void sr_destined_for_router(struct sr_instance *sr, uint8_t *packet, unsigned int len, char *interface, struct sr_if *outgoing_iface, int echo)
{
  struct sr_if *incoming_iface = sr_get_interface(sr, interface);

  // Create ICMP packet
  size_t icmp_packet_len;
  if (echo == 1) { // if it's an echo request
    printf("Creating ICMP echo reply\n");
    icmp_packet_len = len; // same length as original packet, because it's an echo
  } else { // if it's not an echo request
    printf("Creating ICMP destination unreachable\n");
    icmp_packet_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t); // ICMP packet length
  }
  uint8_t *icmp_packet = (uint8_t *)malloc(icmp_packet_len);
  if (!icmp_packet)
  {
    fprintf(stderr, "Failed to allocate memory for ICMP packet\n");
    return;
  }

  // Get the original IP header and ICMP header
  sr_ip_hdr_t *req_ip_hdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
  sr_icmp_hdr_t *req_icmp_hdr = (sr_icmp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
  
  // start making the packet, starting from ethernet header
  sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)icmp_packet;
  memcpy(eth_hdr->ether_dhost, ((sr_ethernet_hdr_t *)packet)->ether_shost, ETHER_ADDR_LEN); // destination is the original source's mac address
  memcpy(eth_hdr->ether_shost, incoming_iface->addr, ETHER_ADDR_LEN); // source is the router's interface's mac address
  eth_hdr->ether_type = htons(ethertype_ip);
  

  // Populate ICMP header
  sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t *)(icmp_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
  if (echo == 0) 
  {
    printf("Creating ICMP destination unreachable since ECHO==0\n");
    icmp_hdr->icmp_type = 3; // Destination Unreachable
    icmp_hdr->icmp_code = 3; // Port Unreachable
    memcpy(icmp_hdr->data, (uint8_t *) req_ip_hdr, ICMP_DATA_SIZE); // Copy original data
  }
  else
  {
    printf("Creating ICMP echo reply since ECHO==1\n");
    size_t icmp_hdr_len = icmp_packet_len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t);
    memcpy(icmp_hdr, req_icmp_hdr, icmp_hdr_len); // Copy original ICMP header
    icmp_hdr->icmp_type = 0; // Echo Reply
    icmp_hdr->icmp_code = 0; // No code
  }

  icmp_hdr->icmp_sum = 0; // Checksum is 0

  // Populate IP header
  sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(icmp_packet + sizeof(sr_ethernet_hdr_t));
  ip_hdr->ip_hl = req_ip_hdr->ip_hl;
  ip_hdr->ip_v = req_ip_hdr->ip_v;
  ip_hdr->ip_len = htons(icmp_packet_len - sizeof(sr_ethernet_hdr_t));
  if (echo == 0)
  {
    ip_hdr->ip_off = htons(IP_DF);
  }
  ip_hdr->ip_id = req_ip_hdr->ip_id;
  ip_hdr->ip_ttl = INIT_TTL;
  ip_hdr->ip_p = ip_protocol_icmp;
  ip_hdr->ip_sum = 0; // Checksum is 0
  ip_hdr->ip_src = outgoing_iface->ip; // Source is the router's IP
  ip_hdr->ip_dst = req_ip_hdr->ip_src; // Destination is the original source's IP
  

  // recompute checksums
  ip_hdr->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));
  if (echo == 1) {
    size_t icmp_hdr_len = icmp_packet_len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t);
    icmp_hdr->icmp_sum = cksum(icmp_hdr, icmp_hdr_len);
  } else {
    icmp_hdr->icmp_sum = cksum(icmp_hdr, sizeof(sr_icmp_hdr_t));
  }

  // Send
  print_hdrs(icmp_packet, icmp_packet_len);
  if (sr_send_packet(sr, icmp_packet, icmp_packet_len, interface) == -1)
  {
    fprintf(stderr, "Failed to send ICMP packet\n");
  }
  else
  {
    //printf("sr_destined_for_router: Sent ICMP packet\n");
  }
  //free(icmp_packet);

} /* end sr_destined_for_router */

void sr_handle_arprequest(struct sr_instance *sr, sr_arp_hdr_t *arp_pkt, unsigned int len,
                          char *interface, uint8_t *packet) //arp_pkt = arp_packet
{

  // answers the question "Who has IP of router, send me your mac address" with "I'm the router, I have that IP, here is my mac address"

  // check if target IP address is the router's IP address:
  struct sr_if *matching_iface = get_interface_from_ip(sr, arp_pkt->ar_tip); //cur_if

  if (matching_iface == NULL)
  { // router can have multiple interfaces for different networks, so search through them
    printf("sr_handle_arprequest: ARP request not for us\n");
    return;
  }

  // printf("sr_handle_arprequest: creating arp reply to target: %u\n", arp_pkt->ar_tip);

  uint8_t *arp_reply = (uint8_t *)malloc(len); // same length as original arp packet

  // Ethernet Headers
  struct sr_ethernet_hdr *ethernet_hdr = (struct sr_ethernet_hdr *)arp_reply;
  memcpy(ethernet_hdr->ether_dhost, ((sr_ethernet_hdr_t *)packet)->ether_shost, ETHER_ADDR_LEN); // broadcast
  memcpy(ethernet_hdr->ether_shost, matching_iface->addr, ETHER_ADDR_LEN);                       // mac address that matches the interface for router
  ethernet_hdr->ether_type = htons(ethertype_arp);

  sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *)(arp_reply + sizeof(struct sr_ethernet_hdr));
  arp_hdr->ar_hrd = htons(arp_hrd_ethernet);
  arp_hdr->ar_pro = htons(ethertype_ip);
  arp_hdr->ar_hln = ETHER_ADDR_LEN;
  arp_hdr->ar_pln = 4;
  arp_hdr->ar_op = htons(arp_op_reply);
  memcpy(arp_hdr->ar_sha, matching_iface->addr, ETHER_ADDR_LEN);
  arp_hdr->ar_sip = matching_iface->ip;
  memcpy(arp_hdr->ar_tha, ((sr_ethernet_hdr_t *)packet)->ether_shost, ETHER_ADDR_LEN); // whys hould this be ((sr_ethernet_hdr_t *) packet)->ether_shost, instead
  arp_hdr->ar_tip = arp_pkt->ar_sip;

  if (sr_send_packet(sr, arp_reply, len, interface) == -1)
  {
    fprintf(stderr, "Failed to send ARP reply\n");
  } else {
    // printf("sr_handle_arprequest: Sent ARP reply for IP: %u\n", arp_pkt->ar_sip);
  }
  free(arp_reply);
}

/*
  It checks if the IP address in the received ARP reply is already present in the request queue. If found, it removes this request from the queue (to avoid redundant requests) and returns it.
  It then updates the ARP cache with the new IP-to-MAC mapping, marking it as valid.
*/
void sr_handle_arpreply(struct sr_instance *sr, sr_arp_hdr_t *arp_pkt, unsigned int len,
                        char *interface)
{
  // responds to answer of "Hey router, I have that IP, and this is my MAC address" with "Okay, here are all the packets that were meant for you"
  // In arpcache.c, I actually implement the part where the router asks, "Hey I'm the router, and I'm looking for mac address that corresponds to <ARP request's IP>"

  // check if the ARP reply is for us
  struct sr_if *matching_iface = get_interface_from_ip(sr, arp_pkt->ar_tip);
  if (matching_iface == NULL)
  { // the ARP reply is not for us
    printf("sr_handle_arpreply: ARP reply not for us\n");
    return;
  }

  // Check if IP address is already in the request queue
  struct sr_arpreq *request = sr_arpcache_insert(&sr->cache, arp_pkt->ar_sha, arp_pkt->ar_sip);
  if (request)
  {
    // If found, send off all packets on the request's pending packets list, then remove the request from the queue
    printf("sr_handle_arpreply: Found matching request for IP: %u\n", arp_pkt->ar_sip);
    struct sr_packet *cur_pkt = request->packets;
    while (cur_pkt)
    {
      // send the packet

      // arp_pkt contains the destination mac address, since it's the arp reply
      sr_ethernet_hdr_t *ethernet_hdr = (sr_ethernet_hdr_t *)cur_pkt->buf;
      memcpy(ethernet_hdr->ether_dhost, arp_pkt->ar_sha, ETHER_ADDR_LEN);      // destination is the mac address from the arp reply
      memcpy(ethernet_hdr->ether_shost, matching_iface->addr, ETHER_ADDR_LEN); // source is the router's interface's mac address

      if (sr_send_packet(sr, cur_pkt->buf, cur_pkt->len, matching_iface->name) == -1)
      {
        fprintf(stderr, "ARP Reply: Failed to send queued packet\n");
      } else {
        printf("Sent queued packet to %u\n", arp_pkt->ar_sip);
      }
      cur_pkt = cur_pkt->next;
    }
    sr_arpreq_destroy(&sr->cache, request);
  }

  // Insert the MAC address & corresponing IP into the ARP cache
}



void sr_handle_ip_forwarding(struct sr_instance *sr, uint8_t *forward_pkt, unsigned int len, char *interface)
{
  // handle IP forwarding logic here
  // decrement TTL by 1

  // prepare error messages ICMP type 11 and 3, all error messages will be sent directly back to sender, so send them out the same incoming interface
  struct sr_if *incoming_if = sr_get_interface(sr, interface);

  size_t error_pkt_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t);
  uint8_t *error_pkt = (uint8_t *)malloc(error_pkt_len);

  // grab headers of error packet
  sr_icmp_hdr_t *error_icmp_hdr = (sr_icmp_hdr_t *)(error_pkt + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

  // create packet
  create_ip_forwarding_error_packet(error_pkt, forward_pkt, incoming_if, error_pkt_len); // fill in ip_hdr and eth_hdr of error_pkt
  
  sr_ip_hdr_t *forward_ip_hdr = (sr_ip_hdr_t *)(forward_pkt + sizeof(sr_ethernet_hdr_t));
  (forward_ip_hdr->ip_ttl)--;
  forward_ip_hdr->ip_sum = 0;
  forward_ip_hdr->ip_sum = cksum(forward_ip_hdr, sizeof(sr_ip_hdr_t)); // supposed to do this at the END

  // fill in some ICMP fields
  error_icmp_hdr->icmp_sum = 0;
  memcpy(error_icmp_hdr->data, forward_ip_hdr, ICMP_DATA_SIZE); // copy the data from the updated forward packet
  // error functions will handle the rest, including checksums and icmp types and codes

  // check TTL  expiration
  if (forward_ip_hdr->ip_ttl < 1)
  {
    printf("TTL expired. Sending ICMP Time Exceeded.\n");
    // SEND ICMP TIME EXCEEDED PACKET
    icmp_11_error(sr, error_pkt, error_pkt_len, interface);
  }
  else
  {
    printf("TTL is %d. Packet can be forwarded.\n", forward_ip_hdr->ip_ttl);
  }

  // Find match for destination IP in routing table...
  // next_hop_mac_address = (matching function result)

  struct sr_rt *rt = sr->routing_table; // get routing table
  while( rt != NULL ) {
    if (rt->dest.s_addr == forward_ip_hdr->ip_dst) {
      break;
    }
    rt = rt->next;
  }

  if (rt == NULL)
  {
    // send ICMP destination net unreachable
    printf("No route found. Sending ICMP Destination Unreachable.\n");
    icmp_3_error(sr, error_pkt, error_pkt_len, interface);
  }
  free(error_pkt);
  struct sr_if *outgoing_if = sr_get_interface(sr, rt->interface); // rt tells you you need to send 192.168.1.10 to interface eth0, where it's 192.168.1.0

  struct sr_arpentry *entry = sr_arpcache_lookup(&sr->cache, forward_ip_hdr->ip_dst); // cache tells you 192.168.1.1 has mac address AAA...
  if (entry)
  {
    // send to next hop, just redo the layer 2 header of forward_ip_pkt, keep all else
    printf("MAC address found. Forwarding packet to next hop.\n");
    forward_packet(sr, len, outgoing_if, forward_pkt, entry);
  }
  else
  {
    // No ARP entry was found, prepare packet to be placed into queue
    memset(((sr_ethernet_hdr_t *)forward_pkt)->ether_dhost, 0, ETHER_ADDR_LEN);

    // Place packet into the cache's queue, send ARP request
    struct sr_arpreq *arp_req = sr_arpcache_queuereq(&sr->cache, forward_ip_hdr->ip_dst, forward_pkt, len, outgoing_if->name);
    printf("No ARP entry found. Sending ARP request.\n");
    handle_arpreq(sr, arp_req);

  }
}

void icmp_11_error(struct sr_instance *sr, uint8_t *error_pkt, size_t error_len, char *interface)
{
  sr_icmp_hdr_t *error_icmp_hdr = (sr_icmp_hdr_t *)(error_pkt + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
  sr_ip_hdr_t *error_ip_hdr = (sr_ip_hdr_t *)(error_pkt + sizeof(sr_ethernet_hdr_t));

  // send ICMP time exceeded packet
  error_icmp_hdr->icmp_type = 11;
  error_icmp_hdr->icmp_code = 0;

  // recompute checksums
  error_ip_hdr->ip_sum = cksum(error_ip_hdr, sizeof(sr_ip_hdr_t));
  error_icmp_hdr->icmp_sum = cksum(error_icmp_hdr, sizeof(sr_icmp_hdr_t));

  if (sr_send_packet(sr, error_pkt, error_len, interface) == -1)
  {
    fprintf(stderr, "Failed to send ICMP Time Exceeded\n");
  }
  // free(error_pkt);
  return;
}

void icmp_3_error(struct sr_instance *sr, uint8_t *error_pkt, size_t error_len, char *interface)
{
  sr_icmp_hdr_t *error_icmp_hdr = (sr_icmp_hdr_t *)(error_pkt + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
  sr_ip_hdr_t *error_ip_hdr = (sr_ip_hdr_t *)(error_pkt + sizeof(sr_ethernet_hdr_t));

  // send ICMP destination unreachable packet
  error_icmp_hdr->icmp_type = 3;
  error_icmp_hdr->icmp_code = 0;

  // recompute checksums
  error_ip_hdr->ip_sum = cksum(error_ip_hdr, sizeof(sr_ip_hdr_t));
  error_icmp_hdr->icmp_sum = cksum(error_icmp_hdr, sizeof(sr_icmp_hdr_t));

  if (sr_send_packet(sr, error_pkt, error_len, interface) == -1)
  {
    fprintf(stderr, "Failed to send ICMP Destination Unreachable\n");
  }
  // free(error_pkt);
  return;
}

void create_ip_forwarding_error_packet(uint8_t *error_pkt, uint8_t *forward_pkt, struct sr_if *incoming_if,
                                       size_t error_pkt_len)
{

  sr_ip_hdr_t *error_ip_hdr = (sr_ip_hdr_t *)(error_pkt + sizeof(sr_ethernet_hdr_t));
  sr_icmp_hdr_t *error_icmp_hdr = (sr_icmp_hdr_t *)(error_pkt + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
  sr_ethernet_hdr_t *error_eth_hdr = (sr_ethernet_hdr_t *)error_pkt;

  // make ethernet headers
  memcpy(error_eth_hdr->ether_dhost, ((sr_ethernet_hdr_t *)forward_pkt)->ether_shost, ETHER_ADDR_LEN);
  memcpy(error_eth_hdr->ether_shost, incoming_if->addr, ETHER_ADDR_LEN);
  error_eth_hdr->ether_type = htons(ethertype_ip);

  // grab ip header of forward packet again
  sr_ip_hdr_t *forward_ip_hdr = (sr_ip_hdr_t *)(forward_pkt + sizeof(sr_ethernet_hdr_t)); //hop_ip_hdr

  // make IP headers
  error_ip_hdr->ip_hl = forward_ip_hdr->ip_hl;
  error_ip_hdr->ip_v = forward_ip_hdr->ip_v;
  error_ip_hdr->ip_len = htons(error_pkt_len - sizeof(sr_ethernet_hdr_t));
  error_ip_hdr->ip_id = forward_ip_hdr->ip_id;
  error_ip_hdr->ip_off = htons(IP_DF);
  error_ip_hdr->ip_ttl = INIT_TTL;
  error_ip_hdr->ip_p = ip_protocol_icmp;
  error_ip_hdr->ip_src = incoming_if->ip;
  error_ip_hdr->ip_dst = forward_ip_hdr->ip_src;

  error_ip_hdr->ip_sum = 0;

  // icmp header will be handled in the error message functions
}

void forward_packet(struct sr_instance *sr, unsigned int len, struct sr_if *outgoing_if, uint8_t *forward_pkt, struct sr_arpentry *entry)
{
  memcpy(((sr_ethernet_hdr_t *)forward_pkt)->ether_dhost, entry->mac, ETHER_ADDR_LEN);
  memcpy(((sr_ethernet_hdr_t *)forward_pkt)->ether_shost, outgoing_if->addr, ETHER_ADDR_LEN);

  if (sr_send_packet(sr, forward_pkt, len, outgoing_if->name) == -1)
  {
    fprintf(stderr, "Failed to send Forwarding IP Packet\n");
  }
  free(entry);
}