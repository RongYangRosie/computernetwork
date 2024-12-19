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
void forward_ip_packet(struct sr_instance *sr, uint8_t *packet, unsigned int len,
                       struct sr_if *out_iface, uint8_t *dest_mac);
int validate_packet_headers(uint8_t *packet, unsigned int len, uint16_t expected_ethertype);
void handle_arp_reply(struct sr_instance *sr, sr_arp_hdr_t *arp_hdr, struct sr_if *iface);

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

void sr_handlepacket(struct sr_instance *sr,
                     uint8_t *packet,
                     unsigned int len,
                     char *interface)
{
  /* Basic validation */
  if (!sr || !packet || !interface || len < sizeof(sr_ethernet_hdr_t))
  {
    fprintf(stderr, "Error: Invalid packet parameters\n");
    return;
  }

  struct sr_if *iface = sr_get_interface(sr, interface);
  if (!iface)
  {
    fprintf(stderr, "Error: Interface %s not found\n", interface);
    return;
  }

  sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)packet;
  uint16_t ethtype = ntohs(eth_hdr->ether_type);

  /* Handle ARP */
  if (ethtype == ethertype_arp)
  {
    if (len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t))
    {
      fprintf(stderr, "Error: ARP packet too short\n");
      return;
    }

    sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
    uint16_t op = ntohs(arp_hdr->ar_op);

    if (op == arp_op_request && arp_hdr->ar_tip == iface->ip)
    {
      // Cache the sender's info before replying
      pthread_mutex_lock(&sr->cache.lock);
      sr_arpcache_insert(&sr->cache, arp_hdr->ar_sha, arp_hdr->ar_sip);
      pthread_mutex_unlock(&sr->cache.lock);

      send_arp_reply(sr, iface, arp_hdr, eth_hdr);
    }
    else if (op == arp_op_reply)
    {
      handle_arp_reply(sr, arp_hdr, iface);
    }
    return;
  }

  /* Handle IP */
  if (ethtype == ethertype_ip)
  {
    if (!validate_packet_headers(packet, len, ethertype_ip))
    {
      fprintf(stderr, "Error: Invalid IP packet headers\n");
      return;
    }

    sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));

    // Check if packet is destined for us
    struct sr_if *target_iface = sr->if_list;
    while (target_iface)
    {
      if (target_iface->ip == ip_hdr->ip_dst)
      {
        handle_ip_packet(sr, packet, len, target_iface);
        return;
      }
      target_iface = target_iface->next;
    }

    // Forward packet
    if (ip_hdr->ip_ttl <= 1)
    {
      icmp_err(sr, packet, 11, 0, iface, eth_hdr, ip_hdr); // TTL expired
      return;
    }

    // Decrement TTL and update checksum
    ip_hdr->ip_ttl--;
    ip_hdr->ip_sum = 0;
    ip_hdr->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));

    struct sr_if *out_iface = dest_iface(sr, ip_hdr->ip_dst);
    if (!out_iface)
    {
      icmp_err(sr, packet, 3, 0, iface, eth_hdr, ip_hdr); // Network unreachable
      return;
    }

    // Look up next hop MAC
    pthread_mutex_lock(&sr->cache.lock);
    struct sr_arpentry *arp_entry = sr_arpcache_lookup(&sr->cache, ip_hdr->ip_dst);

    if (arp_entry)
    {
      forward_ip_packet(sr, packet, len, out_iface, arp_entry->mac);
      free(arp_entry);
      pthread_mutex_unlock(&sr->cache.lock);
    }
    else
    {
      struct sr_arpreq *req = sr_arpcache_queuereq(&sr->cache, ip_hdr->ip_dst,
                                                   packet, len, out_iface->name);
      pthread_mutex_unlock(&sr->cache.lock);
      handle_arpreq(sr, req);
    }
  }
}

/* Add any additional helper methods here & don't forget to also declare
them in sr_router.h.

If you use any of these methods in sr_arpcache.c, you must also forward declare
them in sr_arpcache.h to avoid circular dependencies. Since sr_router
already imports sr_arpcache.h, sr_arpcache cannot import sr_router.h -KM */

// get ip header
sr_ip_hdr_t *get_ip_hdr(uint8_t *packet)
{
  sr_ip_hdr_t *iphdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
  return iphdr;
}

void handle_ip_packet(struct sr_instance *sr,
                      uint8_t *packet /* lent */,
                      unsigned int len,
                      struct sr_if *iface)
{
  if (!sr || !packet || !iface)
  {
    printf("Error: NULL parameters in handle_ip_packet\n");
    return;
  }

  // Get headers
  sr_ethernet_hdr_t *ethernet_hdr = (sr_ethernet_hdr_t *)packet;
  sr_ip_hdr_t *ip_hdr = get_ip_hdr(packet);
  uint8_t protocol = ip_hdr->ip_p;

  // Handle ICMP
  if (protocol == ip_protocol_icmp)
  {
    printf("Processing ICMP packet\n");

    // Validate minimum packet length for ICMP
    if (len < (sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t)))
    {
      printf("Error: ICMP packet too small\n");
      return;
    }

    // Get ICMP header - fix pointer arithmetic
    sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

    // ICMP checksum validation
    uint16_t received_checksum = icmp_hdr->icmp_sum;
    icmp_hdr->icmp_sum = 0;
    uint16_t calculated_checksum = cksum(icmp_hdr, ntohs(ip_hdr->ip_len) - sizeof(sr_ip_hdr_t));

    if (calculated_checksum != received_checksum)
    {
      printf("Error: ICMP checksum mismatch\n");
      icmp_hdr->icmp_sum = received_checksum; // restore original
      return;
    }

    icmp_hdr->icmp_sum = received_checksum; // restore original

    // Handle Echo Request (ping)
    if (icmp_hdr->icmp_type == 8 && icmp_hdr->icmp_code == 0)
    {
      printf("Handling ICMP echo request\n");
      handle_icmp_echo_request(sr, packet, len, iface);
    }
    else
    {
      printf("Unsupported ICMP type/code: %d/%d\n", icmp_hdr->icmp_type, icmp_hdr->icmp_code);
    }
  }
  // Handle TCP
  else if (protocol == 6)
  {
    printf("TCP packet received - sending port unreachable\n");
    icmp_err(sr, packet, 3, 3, iface, ethernet_hdr, ip_hdr);
  }
  // Handle UDP
  else if (protocol == 17)
  {
    printf("UDP packet received - sending port unreachable\n");
    icmp_err(sr, packet, 3, 3, iface, ethernet_hdr, ip_hdr);
  }
  // Unsupported protocol
  else
  {
    printf("Unsupported protocol number: %d\n", protocol);
    icmp_err(sr, packet, 3, 2, iface, ethernet_hdr, ip_hdr); // Protocol unreachable
  }
}

void icmp_echo(struct sr_instance *sr, uint8_t *packet, unsigned int len, uint32_t dest,
               uint8_t type, uint8_t code, struct sr_if *iface,
               sr_ethernet_hdr_t *ethernet_hdr, sr_ip_hdr_t *ip_hdr,
               sr_icmp_hdr_t *icmp_hdr)
{
  // Validate all pointers first
  if (!sr || !packet || !iface || !ethernet_hdr || !ip_hdr || !icmp_hdr)
  {
    printf("Error: Null pointer in icmp_echo\n");
    return;
  }

  // Get outgoing interface
  struct sr_if *outgoing_iface = dest_iface(sr, ip_hdr->ip_src);
  if (!outgoing_iface)
  {
    printf("Error: Could not find outgoing interface\n");
    return;
  }

  // Validate packet length
  unsigned int min_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t);
  if (len < min_len)
  {
    printf("Error: Packet too short for ICMP echo reply\n");
    return;
  }

  // 1. Update Ethernet header
  memcpy(ethernet_hdr->ether_dhost, ethernet_hdr->ether_shost, ETHER_ADDR_LEN);
  memcpy(ethernet_hdr->ether_shost, outgoing_iface->addr, ETHER_ADDR_LEN);
  ethernet_hdr->ether_type = htons(ethertype_ip);

  // 2. Update IP header
  ip_hdr->ip_src = iface->ip;
  ip_hdr->ip_dst = dest;
  ip_hdr->ip_sum = 0;
  ip_hdr->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));

  // 3. Update ICMP header
  icmp_hdr->icmp_type = type; // Should be 0 for echo reply
  icmp_hdr->icmp_code = code; // Should be 0 for echo reply
  icmp_hdr->icmp_sum = 0;

  // Calculate checksum over the entire ICMP message (header + data)
  unsigned int icmp_len = ntohs(ip_hdr->ip_len) - sizeof(sr_ip_hdr_t);
  icmp_hdr->icmp_sum = cksum(icmp_hdr, icmp_len);

  printf("Sending ICMP echo reply: type=%d, code=%d, len=%d\n", type, code, len);
  int result = sr_send_packet(sr, packet, len, outgoing_iface->name);

  if (result != 0)
  {
    printf("Error: Failed to send ICMP echo reply\n");
  }
}

// Helper function to handle ICMP echo requests
void handle_icmp_echo_request(struct sr_instance *sr, uint8_t *packet,
                              unsigned int len, struct sr_if *iface)
{
  sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)packet;
  sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
  sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

  // Validate ICMP echo request
  if (icmp_hdr->icmp_type != 8 || icmp_hdr->icmp_code != 0)
  {
    printf("Not an ICMP echo request\n");
    return;
  }

  // Send echo reply
  icmp_echo(sr, packet, len, ip_hdr->ip_src, 0, 0, iface, eth_hdr, ip_hdr, icmp_hdr);
}
// icmp error- type 3 or 11 (ttl expired)
void icmp_err(struct sr_instance *sr, uint8_t *packet, uint8_t type, uint8_t code,
              struct sr_if *iface, sr_ethernet_hdr_t *ethernet_hdr, sr_ip_hdr_t *ip_hdr)
{
  printf("in icmp_err\n");
  // Calculate new packet length
  unsigned int new_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);

  // Allocate memory for new packet
  uint8_t *new_packet = (uint8_t *)malloc(new_len);
  if (!new_packet)
  {
    printf("Error: Failed to allocate memory for ICMP error packet\n");
    return;
  }

  // Zero out the new packet
  memset(new_packet, 0, new_len);

  // Set up headers
  sr_ethernet_hdr_t *new_ethernet_hdr = (sr_ethernet_hdr_t *)new_packet;
  sr_ip_hdr_t *new_ip_hdr = (sr_ip_hdr_t *)(new_packet + sizeof(sr_ethernet_hdr_t));
  sr_icmp_t3_hdr_t *new_icmp_hdr = (sr_icmp_t3_hdr_t *)(new_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

  // Get outgoing interface
  struct sr_if *outgoing_iface = dest_iface(sr, ip_hdr->ip_src);
  if (!outgoing_iface)
  {
    printf("Error: Could not find outgoing interface\n");
    free(new_packet);
    return;
  }

  // Fill ethernet header
  memcpy(new_ethernet_hdr->ether_dhost, ethernet_hdr->ether_shost, ETHER_ADDR_LEN);
  memcpy(new_ethernet_hdr->ether_shost, outgoing_iface->addr, ETHER_ADDR_LEN);
  new_ethernet_hdr->ether_type = htons(ethertype_ip);

  // Fill IP header
  new_ip_hdr->ip_v = 4;
  new_ip_hdr->ip_hl = 5;
  new_ip_hdr->ip_tos = 0;
  new_ip_hdr->ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
  new_ip_hdr->ip_id = 0;
  new_ip_hdr->ip_off = htons(IP_DF);
  new_ip_hdr->ip_ttl = INIT_TTL;
  new_ip_hdr->ip_p = ip_protocol_icmp;
  new_ip_hdr->ip_src = outgoing_iface->ip;
  new_ip_hdr->ip_dst = ip_hdr->ip_src;
  new_ip_hdr->ip_sum = 0;
  new_ip_hdr->ip_sum = cksum(new_ip_hdr, sizeof(sr_ip_hdr_t));

  // Fill ICMP header
  new_icmp_hdr->icmp_type = type;
  new_icmp_hdr->icmp_code = code;
  new_icmp_hdr->unused = 0;
  new_icmp_hdr->next_mtu = 0;

  // Copy the original IP header plus first 8 bytes of original payload
  memcpy(new_icmp_hdr->data, ip_hdr, ICMP_DATA_SIZE);

  // Calculate ICMP checksum
  new_icmp_hdr->icmp_sum = 0;
  new_icmp_hdr->icmp_sum = cksum(new_icmp_hdr, sizeof(sr_icmp_t3_hdr_t));

  // Send packet
  int result = sr_send_packet(sr, new_packet, new_len, outgoing_iface->name);
  if (result != 0)
  {
    printf("Error: Failed to send ICMP error packet\n");
  }

  // Free allocated memory
  free(new_packet);
}

/* Function to determine the destination interface based on IP routing table lookup */
struct sr_if *dest_iface(struct sr_instance *sr, uint32_t ip_dst)
{
  struct sr_rt *rt_walker = sr->routing_table;
  struct sr_if *iface = NULL;
  uint32_t longest_match = 0;

  /* Traverse the routing table to find the longest prefix match */
  while (rt_walker)
  {
    /* Perform bitwise AND to check match with destination IP */
    uint32_t masked_dst = ip_dst & rt_walker->mask.s_addr;
    if (masked_dst == (rt_walker->dest.s_addr))
    {
      longest_match = rt_walker->mask.s_addr;
      iface = sr_get_interface(sr, rt_walker->interface);
      return iface;
    }
    rt_walker = rt_walker->next;
  }

  /* If a match was found, return the corresponding interface */
  return iface;
}

// ARP ******

// send arp reply
void send_arp_reply(struct sr_instance *sr, struct sr_if *iface,
                    sr_arp_hdr_t *arphdr, sr_ethernet_hdr_t *ethernet_hdr)
{
  if (!sr || !iface || !arphdr || !ethernet_hdr)
  {
    printf("Error: NULL parameter passed to send_arp_reply\n");
    return;
  }

  /* Create a new packet for the ARP reply */
  unsigned int packet_size = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
  uint8_t *arp_reply_packet = (uint8_t *)malloc(packet_size);
  if (!arp_reply_packet)
  {
    printf("Error: Memory allocation failed for ARP reply\n");
    return;
  }

  /* Fill in Ethernet header */
  sr_ethernet_hdr_t *reply_eth_hdr = (sr_ethernet_hdr_t *)arp_reply_packet;
  memcpy(reply_eth_hdr->ether_dhost, ethernet_hdr->ether_shost, ETHER_ADDR_LEN); // Destination MAC is sender's MAC
  memcpy(reply_eth_hdr->ether_shost, iface->addr, ETHER_ADDR_LEN);               // Source MAC is interface MAC
  reply_eth_hdr->ether_type = htons(ethertype_arp);

  /* Fill in ARP header */
  sr_arp_hdr_t *reply_arp_hdr = (sr_arp_hdr_t *)(arp_reply_packet + sizeof(sr_ethernet_hdr_t));
  reply_arp_hdr->ar_hrd = htons(arp_hrd_ethernet); // Ethernet hardware type
  reply_arp_hdr->ar_pro = htons(ethertype_ip);     // Protocol type for IP
  reply_arp_hdr->ar_hln = ETHER_ADDR_LEN;          // Hardware address length
  reply_arp_hdr->ar_pln = sizeof(uint32_t);        // Protocol address length
  reply_arp_hdr->ar_op = htons(arp_op_reply);      // Set ARP operation to reply

  /* Set sender and target information */
  memcpy(reply_arp_hdr->ar_sha, iface->addr, ETHER_ADDR_LEN);    // Sender MAC address
  reply_arp_hdr->ar_sip = iface->ip;                             // Sender IP address
  memcpy(reply_arp_hdr->ar_tha, arphdr->ar_sha, ETHER_ADDR_LEN); // Target MAC address (from ARP request)
  reply_arp_hdr->ar_tip = arphdr->ar_sip;                        // Target IP address (from ARP request)

  /* Send the ARP reply packet */
  int res = sr_send_packet(sr, arp_reply_packet, packet_size, iface->name);
  if (res < 0)
  {
    printf("Error: Failed to send ARP reply\n");
  }
  else
  {
    printf("Sent ARP reply to %s\n", iface->name);
  }

  free(arp_reply_packet); // Free allocated memory for the reply packet
}

  void send_arp_request(struct sr_instance *sr, uint32_t ip)
  {
    printf("in send_arp_request...\n");

    // 1. Get the outgoing interface before allocating memory
    struct sr_if *iface = dest_iface(sr, ip);
    if (!iface)
    {
      printf("Error: Could not find outgoing interface\n");
      return;
    }

    // 2. Create empty packet
    unsigned int len = sizeof(sr_arp_hdr_t) + sizeof(sr_ethernet_hdr_t);
    uint8_t *packet = (uint8_t *)malloc(len);
    if (!packet)
    {
      printf("Error: Failed to allocate memory for ARP request\n");
      return;
    }
    memset(packet, 0, len); // Use memset instead of bzero for clarity

    // 3. Set up headers
    struct sr_ethernet_hdr *eth_hdr = (sr_ethernet_hdr_t *)packet;
    struct sr_arp_hdr *arp_hdr = (sr_arp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));

    // 4. Fill ethernet header
    // Set broadcast address for destination
    memset(eth_hdr->ether_dhost, 0xFF, ETHER_ADDR_LEN); // Broadcast address
    memcpy(eth_hdr->ether_shost, iface->addr, ETHER_ADDR_LEN);
    eth_hdr->ether_type = htons(ethertype_arp);

    // 5. Fill ARP header
    arp_hdr->ar_hrd = htons(arp_hrd_ethernet);
    arp_hdr->ar_pro = htons(ethertype_ip);
    arp_hdr->ar_hln = ETHER_ADDR_LEN;
    arp_hdr->ar_pln = 4;
    arp_hdr->ar_op = htons(arp_op_request); // REQUEST not REPLY

    // Set sender hardware address (our MAC)
    memcpy(arp_hdr->ar_sha, iface->addr, ETHER_ADDR_LEN);
    // Set sender IP (our IP)
    arp_hdr->ar_sip = iface->ip;
    // Set target hardware address to 0 (what we're trying to find out)
    memset(arp_hdr->ar_tha, 0, ETHER_ADDR_LEN);
    // Set target IP (IP we're looking for)
    arp_hdr->ar_tip = ip;

    // 6. Send the packet
    int result = sr_send_packet(sr, packet, len, iface->name);
    if (result != 0)
    {
      printf("Error: Failed to send ARP request\n");
    } else {
      printf("sent packet\n");
    }

    // 7. Clean up
    free(packet);
  }
  // **GENERAL

  // forward packet
  void forward_packet(struct sr_instance *sr, uint8_t *packet, unsigned int len, struct sr_if *iface, uint8_t *dest, sr_ethernet_hdr_t *ethernet_hdr, sr_ip_hdr_t *ip_hdr)
  {
    // Validate minimum packet length
    if (len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t))
    {
      printf("Error: Packet too short for forwarding\n");
      return;
    }

    // Create new Ethernet header
    sr_ethernet_hdr_t new_ethernet_hdr;
    memcpy(new_ethernet_hdr.ether_dhost, dest, ETHER_ADDR_LEN);
    memcpy(new_ethernet_hdr.ether_shost, iface->addr, ETHER_ADDR_LEN);
    new_ethernet_hdr.ether_type = ethernet_hdr->ether_type;

    // Create new IP header
    sr_ip_hdr_t new_ip_hdr;
    memcpy(&new_ip_hdr, ip_hdr, sizeof(sr_ip_hdr_t));
    new_ip_hdr.ip_sum = 0;
    new_ip_hdr.ip_sum = cksum(&new_ip_hdr, sizeof(sr_ip_hdr_t));

    // Append the new headers to the packet
    uint8_t *new_packet = (uint8_t *)malloc(len);
    if (!new_packet)
    {
      printf("Error: Failed to allocate memory for forwarded packet\n");
      return;
    }
    memcpy(new_packet, &new_ethernet_hdr, sizeof(sr_ethernet_hdr_t));
    memcpy(new_packet + sizeof(sr_ethernet_hdr_t), &new_ip_hdr, sizeof(sr_ip_hdr_t));
    memcpy(new_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t), packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t), len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t));

    // Send the forwarded packet
    int result = sr_send_packet(sr, new_packet, len, iface->name);
    if (result != 0)
    {
      printf("Error: Failed to send forwarded packet\n");
    }

    free(new_packet);
  }
  void handle_arp_reply(struct sr_instance *sr, sr_arp_hdr_t *arp_hdr, struct sr_if *iface)
  {
    if (arp_hdr->ar_tip != iface->ip)
    {
      return; // Not for us
    }

    pthread_mutex_lock(&sr->cache.lock);
    struct sr_arpreq *req = sr_arpcache_insert(&sr->cache, arp_hdr->ar_sha, arp_hdr->ar_sip);

    if (req)
    {
      struct sr_packet *pkt;
      for (pkt = req->packets; pkt; pkt = pkt->next)
      {
        struct sr_if *out_iface = sr_get_interface(sr, pkt->iface);
        if (out_iface)
        {
          forward_ip_packet(sr, pkt->buf, pkt->len, out_iface, arp_hdr->ar_sha);
        }
      }
      sr_arpreq_destroy(&sr->cache, req);
    }
    pthread_mutex_unlock(&sr->cache.lock);
  }
  void forward_ip_packet(struct sr_instance *sr, uint8_t *packet, unsigned int len,
                                struct sr_if *out_iface, uint8_t *dest_mac)
  {
    if (!sr || !packet || !out_iface || !dest_mac || len < sizeof(sr_ethernet_hdr_t))
    {
      return;
    }

    sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)packet;

    // Update Ethernet header in place
    memcpy(eth_hdr->ether_dhost, dest_mac, ETHER_ADDR_LEN);
    memcpy(eth_hdr->ether_shost, out_iface->addr, ETHER_ADDR_LEN);

    if (sr_send_packet(sr, packet, len, out_iface->name) != 0)
    {
      fprintf(stderr, "Error: Failed to forward packet on interface %s\n", out_iface->name);
    }
  }
  int validate_packet_headers(uint8_t *packet, unsigned int len, uint16_t expected_ethertype) {
    if (len < sizeof(sr_ethernet_hdr_t))
    {
      return 0;
    }

    sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)packet;
    if (ntohs(eth_hdr->ether_type) != expected_ethertype)
    {
      return 0;
    }

    if (expected_ethertype == ethertype_ip)
    {
      if (len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t))
      {
        return 0;
      }

      sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
      uint16_t orig_sum = ip_hdr->ip_sum;
      ip_hdr->ip_sum = 0;
      uint16_t calc_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));
      ip_hdr->ip_sum = orig_sum;

      return calc_sum == orig_sum;
    }

    return 1;
  }
