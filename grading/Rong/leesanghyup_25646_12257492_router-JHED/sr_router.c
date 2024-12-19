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

#include "sr_router.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "sr_arpcache.h"
#include "sr_if.h"
#include "sr_protocol.h"
#include "sr_rt.h"
#include "sr_utils.h"

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance *sr) {
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

void sr_handlepacket(struct sr_instance *sr, uint8_t *packet /* lent */,
                     unsigned int len, char *interface /* lent */) {
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  printf("*** -> Received packet of length %d \n", len);


  sr_arpcache_sweepreqs(sr);

  if (len < sizeof(sr_ethernet_hdr_t)) {
    fprintf(stderr, "Packet too short for Ethernet header\n");
    return;
  }

  // Create Ethernet Header
  uint16_t eth_type = ethertype(packet);
  //print_hdr_eth(packet);

  if (eth_type == ethertype_ip) {
    printf("Processing IP Packet\n");

    // Error Checking
    if (len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)) {
      fprintf(stderr, "Failed to contain IP Packet!\n");
      return;
    }

    sr_ip_hdr_t *ipptr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
    //print_hdr_ip((uint8_t *)ipptr);

    if (!calculate_checksum(ipptr)) {
      fprintf(stderr, "Checksum Failed!\n");
      return;
    }

    uint32_t destination = ipptr->ip_dst;
    struct sr_if *iface = get_interface_from_ip(sr, destination);

    if (iface) {
      if (ipptr->ip_p == ip_protocol_icmp) {
        // It's an ICMP packet, handle it accordingly
        sr_icmp_hdr_t *icmp_hdr =
            (sr_icmp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) +
                              ipptr->ip_hl * 4);

        uint16_t icmp_len = ntohs(ipptr->ip_len) - ipptr->ip_hl * 4;
        uint16_t received_icmp_checksum = icmp_hdr->icmp_sum;
        icmp_hdr->icmp_sum = 0;
        if (cksum(icmp_hdr, icmp_len) != received_icmp_checksum) {
          fprintf(stderr, "Invalid ICMP checksum, dropping packet\n");
          return;
        }
        icmp_hdr->icmp_sum = received_icmp_checksum;

        if (icmp_hdr->icmp_type == 8) {
          // ICMP Echo Request (type 8), respond with ICMP Echo Reply (type 0)
          send_icmp_echo_reply(sr, packet, len, interface);
        } else {
          // Not an Echo Request, ignore the ICMP packet
          printf(
              "Received ICMP packet that is not an Echo Request. Dropping "
              "it.\n");
        }
      } else {
        // Non-ICMP packet received on the router, send ICMP Port Unreachable
        send_icmp_message(sr, packet, len, interface, 3, 3);
      }
    } else {
      // IP forwarding
      // Decrement TTL
      ipptr->ip_ttl--;

      // TTL expired
      if (ipptr->ip_ttl <= 0) {
        send_icmp_message(sr, packet, len, interface, 11, 0);
        return;
      }

      // Recalculate checksum after modifying TTL
      ipptr->ip_sum = 0;
      ipptr->ip_sum = cksum((uint8_t *)ipptr, ipptr->ip_hl * 4);

      // Find routing entry
      struct sr_rt *be = sr_find_rt_entry(sr, ipptr->ip_dst);
      if (be == NULL) {
        printf("No routing table entry found for IP: %s\n",
               inet_ntoa(*(struct in_addr *)&(ipptr->ip_dst)));
        send_icmp_message(sr, packet, len, interface, 3, 0);
        return;
      } else {
        uint32_t next_hop_ip;
        if (be->gw.s_addr != 0) {
          next_hop_ip = be->gw.s_addr;
        } else {
          next_hop_ip = ipptr->ip_dst;
        }

        printf("Routing entry found. Next hop IP: %s\n",
               inet_ntoa(*(struct in_addr *)&next_hop_ip));

        struct sr_arpentry *cache_entry =
            sr_arpcache_lookup(&sr->cache, next_hop_ip);
        if (cache_entry) {
          printf("ARP entry found\n");
          // ARP entry found, use the MAC address to forward the packet
          forward_packet(sr, packet, len, cache_entry->mac, be->interface);
          free(cache_entry);
        } else {
          // ARP entry not found, queue the ARP request and hold the packet
          printf(
              "ARP entry not found, queuing packet and sending ARP request\n");

          struct sr_arpreq *req = sr_arpcache_queuereq(
              &sr->cache, next_hop_ip, packet, len, be->interface);
          handle_arpreq(sr, req);
        }
      }
    }
  } else if (eth_type == ethertype_arp) {
    printf("Processing ARP Packet\n");

    // ERROR CHECKING
    if (len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t)) {
      fprintf(stderr, "Fails to contain ARP Packet\n");
      return;
    }

    sr_arp_hdr_t *arpprt = (sr_arp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
    //print_hdr_arp((u_int8_t *)arpprt);

    // Check operation to see if it is request or reply
    if (ntohs(arpprt->ar_op) == arp_op_request) {
      // Handle ARP request
      struct sr_if *iface = get_interface_from_ip(sr, arpprt->ar_tip);

      if (iface) {
        // Target IP is one of our IPs, so send an ARP reply
        sr_send_arp_reply(sr, iface, arpprt);
      } else {
        printf(
            "ARP request dropped: Target IP is not one of our router's IPs.\n");
      }
    } else if (ntohs(arpprt->ar_op) == arp_op_reply) {
      // Handle ARP reply
      printf("Handling ARP Reply\n");

      // Cache the ARP reply
      struct sr_arpreq *req =
          sr_arpcache_insert(&sr->cache, arpprt->ar_sha, arpprt->ar_sip);

      // If there is a waiting request, send queued packets and remove the
      // request
      if (req) {
        printf("Processing queued packets for this ARP reply\n");
        struct sr_packet *waiting_packet = req->packets;
        while (waiting_packet) {
          // Update the Ethernet header with the destination MAC from the ARP
          // reply
          sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)waiting_packet->buf;
          memcpy(eth_hdr->ether_dhost, arpprt->ar_sha, ETHER_ADDR_LEN);
          struct sr_if *out_iface = sr_get_interface(sr, waiting_packet->iface);
          memcpy(eth_hdr->ether_shost, out_iface->addr, ETHER_ADDR_LEN);

          // Send the packet
          sr_send_packet(sr, waiting_packet->buf, waiting_packet->len,
                         waiting_packet->iface);

          // Move to the next packet in the queue
          waiting_packet = waiting_packet->next;
        }

        // Remove the ARP request from the queue
        sr_arpreq_destroy(&sr->cache, req);
      }
    }
  } else {
    fprintf(stderr, "Unknown Ethernet type: %d\n", eth_type);
  }
} /* end sr_handlepacket */

void sr_send_arp_reply(struct sr_instance *sr, struct sr_if *iface,
                       sr_arp_hdr_t *arp_hdr) {
  uint8_t buffer[sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t)];

  // Construct the Ethernet header
  sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)buffer;
  memcpy(eth_hdr->ether_dhost, arp_hdr->ar_sha, ETHER_ADDR_LEN);
  memcpy(eth_hdr->ether_shost, iface->addr, ETHER_ADDR_LEN);
  eth_hdr->ether_type = htons(ethertype_arp);

  // Construct the ARP header
  sr_arp_hdr_t *arp_reply =
      (sr_arp_hdr_t *)(buffer + sizeof(sr_ethernet_hdr_t));
  arp_reply->ar_hrd = htons(arp_hrd_ethernet);
  arp_reply->ar_pro = htons(ethertype_ip);
  arp_reply->ar_hln = ETHER_ADDR_LEN;
  arp_reply->ar_pln = sizeof(uint32_t);
  arp_reply->ar_op = htons(arp_op_reply);

  // Fill ARP reply with source MAC and IP (our router's info)
  memcpy(arp_reply->ar_sha, iface->addr, ETHER_ADDR_LEN);
  arp_reply->ar_sip = iface->ip;

  // Fill ARP reply with target MAC and IP (sender's info from the request)
  memcpy(arp_reply->ar_tha, arp_hdr->ar_sha, ETHER_ADDR_LEN);
  arp_reply->ar_tip = arp_hdr->ar_sip;

  print_hdr_arp((u_int8_t *)arp_reply);
  // Send the ARP reply
  sr_send_packet(sr, buffer, sizeof(buffer), iface->name);
}

void sr_send_arp_request(struct sr_instance *sr, struct sr_if *iface,
                         uint32_t target_ip) {
  // Allocate a buffer for the ARP request packet
  uint8_t buffer[sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t)];

  // Construct the Ethernet header
  sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)buffer;
  memset(eth_hdr->ether_dhost, 0xff, ETHER_ADDR_LEN);
  memcpy(eth_hdr->ether_shost, iface->addr, ETHER_ADDR_LEN);
  eth_hdr->ether_type = htons(ethertype_arp);

  // Construct the ARP header
  sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *)(buffer + sizeof(sr_ethernet_hdr_t));
  arp_hdr->ar_hrd = htons(arp_hrd_ethernet);
  arp_hdr->ar_pro = htons(ethertype_ip);
  arp_hdr->ar_hln = ETHER_ADDR_LEN;
  arp_hdr->ar_pln = sizeof(uint32_t);
  arp_hdr->ar_op = htons(arp_op_request);

  // Set the sender's MAC and IP addresses
  memcpy(arp_hdr->ar_sha, iface->addr, ETHER_ADDR_LEN);
  arp_hdr->ar_sip = iface->ip;

  // Set the target's MAC and IP addresses
  memset(arp_hdr->ar_tha, 0x00, ETHER_ADDR_LEN);
  arp_hdr->ar_tip = target_ip;

  // Print ARP request header for debugging
  print_hdr_arp((uint8_t *)arp_hdr);

  // Send the ARP request
  sr_send_packet(sr, buffer, sizeof(buffer), iface->name);
}

uint32_t count_leading_ones(uint32_t mask) {
  uint32_t count = 0;
  while (mask & 0x80000000) {
    count++;
    mask <<= 1;
  }
  return count;
}

struct sr_rt *sr_find_rt_entry(struct sr_instance *sr, uint32_t ip_dst_nbo) {
  struct sr_rt *best_match = NULL;
  uint32_t best_mask_len = 0;

  // IP addresses are in network byte order, so no need to convert
  uint32_t ip_dst = ip_dst_nbo;

  struct sr_rt *rt_entry = sr->routing_table;
  while (rt_entry != NULL) {
    uint32_t rt_dest = rt_entry->dest.s_addr;
    uint32_t rt_mask = rt_entry->mask.s_addr;

    // Apply mask to destination IP and routing table entry destination
    if ((ip_dst & rt_mask) == (rt_dest & rt_mask)) {
      uint32_t mask_len = count_leading_ones(ntohl(rt_mask));
      if (mask_len > best_mask_len) {
        best_match = rt_entry;
        best_mask_len = mask_len;
      }
    }

    // Move to the next entry in the routing table
    rt_entry = rt_entry->next;
  }
  // Return the best match or NULL if no match
  return best_match;
}

int calculate_checksum(sr_ip_hdr_t *ipptr) {
  uint16_t csum = ipptr->ip_sum;
  ipptr->ip_sum = 0;

  uint16_t calculated_checksum = cksum((uint8_t *)ipptr, ipptr->ip_hl * 4);
  ipptr->ip_sum = csum;

  if (calculated_checksum != csum) {
    fprintf(stderr, "IP checksum verification failed!\n");
    return 0;  // false
  }
  return 1;  // true
}

void forward_packet(struct sr_instance *sr, uint8_t *packet, unsigned int len,
                    unsigned char *dest_mac, const char *out_iface_name) {
  // Retrieve the outgoing interface structure
  struct sr_if *out_iface = sr_get_interface(sr, out_iface_name);
  if (!out_iface) {
    fprintf(stderr, "Error: Interface %s not found for forwarding packet.\n",
            out_iface_name);
    return;
  }

  // Update the Ethernet header
  sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)packet;
  memcpy(eth_hdr->ether_dhost, dest_mac, ETHER_ADDR_LEN);
  memcpy(eth_hdr->ether_shost, out_iface->addr, ETHER_ADDR_LEN);

  // Send the packet on the specified interface
  if (sr_send_packet(sr, packet, len, out_iface_name) < 0) {
    fprintf(stderr, "Error: Failed to send packet on interface %s\n",
            out_iface_name);
  }
}

void send_icmp_message(struct sr_instance *sr, uint8_t *original_packet,
                       unsigned int len, const char *interface, uint8_t type,
                       uint8_t code) {
  // Extract IP header from the original packet
  sr_ip_hdr_t *orig_ip_hdr =
      (sr_ip_hdr_t *)(original_packet + sizeof(sr_ethernet_hdr_t));

  // Determine the outgoing interface using the routing table
  struct sr_rt *rt_entry = sr_find_rt_entry(sr, orig_ip_hdr->ip_src);
  if (!rt_entry) {
    fprintf(stderr, "No route to host for ICMP message\n");
    return;
  }

  struct sr_if *out_iface = sr_get_interface(sr, rt_entry->interface);
  if (!out_iface) {
    fprintf(stderr, "Failed to get outgoing interface\n");
    return;
  }

  // Calculate total length for Ethernet, IP, and ICMP headers
  unsigned int icmp_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) +
                          sizeof(sr_icmp_t3_hdr_t);
  uint8_t *icmp_packet = (uint8_t *)malloc(icmp_len);
  if (icmp_packet == NULL) {
    fprintf(stderr, "Error: Memory allocation failed for ICMP packet.\n");
    return;
  }

  // Construct Ethernet header
  sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)icmp_packet;
  memcpy(eth_hdr->ether_shost, out_iface->addr, ETHER_ADDR_LEN);
  eth_hdr->ether_type = htons(ethertype_ip);

  // Construct IP header
  sr_ip_hdr_t *ip_hdr =
      (sr_ip_hdr_t *)(icmp_packet + sizeof(sr_ethernet_hdr_t));
  ip_hdr->ip_v = 4;
  ip_hdr->ip_hl = sizeof(sr_ip_hdr_t) / 4;
  ip_hdr->ip_tos = 0;
  ip_hdr->ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
  ip_hdr->ip_id = htons(0);
  ip_hdr->ip_off = htons(IP_DF);
  ip_hdr->ip_ttl = 64;
  ip_hdr->ip_p = ip_protocol_icmp;
  ip_hdr->ip_src = out_iface->ip;
  ip_hdr->ip_dst = orig_ip_hdr->ip_src;
  ip_hdr->ip_sum = 0;
  ip_hdr->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));

  // Construct ICMP header
  sr_icmp_t3_hdr_t *icmp_hdr =
      (sr_icmp_t3_hdr_t *)(icmp_packet + sizeof(sr_ethernet_hdr_t) +
                           sizeof(sr_ip_hdr_t));
  icmp_hdr->icmp_type = type;
  icmp_hdr->icmp_code = code;
  icmp_hdr->unused = 0;
  icmp_hdr->next_mtu = 0;
  memcpy(icmp_hdr->data, orig_ip_hdr, ICMP_DATA_SIZE);
  icmp_hdr->icmp_sum = 0;
  icmp_hdr->icmp_sum = cksum(icmp_hdr, sizeof(sr_icmp_t3_hdr_t));

  // Determine next hop IP
  uint32_t next_hop_ip =
      (rt_entry->gw.s_addr != 0) ? rt_entry->gw.s_addr : orig_ip_hdr->ip_src;

  // Check ARP cache
  struct sr_arpentry *arp_entry = sr_arpcache_lookup(&sr->cache, next_hop_ip);

  if (arp_entry) {
    memcpy(eth_hdr->ether_dhost, arp_entry->mac, ETHER_ADDR_LEN);
    sr_send_packet(sr, icmp_packet, icmp_len, out_iface->name);
    free(arp_entry);
    free(icmp_packet);
  } else {
    struct sr_arpreq *req = sr_arpcache_queuereq(
        &sr->cache, next_hop_ip, icmp_packet, icmp_len, out_iface->name);
    handle_arpreq(sr, req);
  }
}

void send_icmp_echo_reply(struct sr_instance *sr, uint8_t *original_packet,
                          unsigned int len, const char *interface) {
  // Allocate memory for the ICMP Echo Reply
  uint8_t *icmp_reply = (uint8_t *)malloc(len);
  memcpy(icmp_reply, original_packet, len);

  // Update the Ethernet header
  sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)icmp_reply;
  sr_ethernet_hdr_t *orig_eth_hdr = (sr_ethernet_hdr_t *)original_packet;
  memcpy(eth_hdr->ether_dhost, orig_eth_hdr->ether_shost, ETHER_ADDR_LEN);
  memcpy(eth_hdr->ether_shost, orig_eth_hdr->ether_dhost, ETHER_ADDR_LEN);

  // Update the IP header
  sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(icmp_reply + sizeof(sr_ethernet_hdr_t));
  sr_ip_hdr_t *orig_ip_hdr =
      (sr_ip_hdr_t *)(original_packet + sizeof(sr_ethernet_hdr_t));

  ip_hdr->ip_dst = orig_ip_hdr->ip_src;
  ip_hdr->ip_src = orig_ip_hdr->ip_dst;
  ip_hdr->ip_ttl = 64;
  ip_hdr->ip_sum = 0;
  ip_hdr->ip_sum = cksum(ip_hdr, ip_hdr->ip_hl * 4);

  // Update the ICMP header
  sr_icmp_hdr_t *icmp_hdr =
      (sr_icmp_hdr_t *)(icmp_reply + sizeof(sr_ethernet_hdr_t) +
                        ip_hdr->ip_hl * 4);
  icmp_hdr->icmp_type = 0;
  icmp_hdr->icmp_code = 0;
  icmp_hdr->icmp_sum = 0;
  uint16_t icmp_len = ntohs(ip_hdr->ip_len) - ip_hdr->ip_hl * 4;
  icmp_hdr->icmp_sum = cksum(icmp_hdr, icmp_len);

  // Determine the outgoing interface using the routing table
  struct sr_rt *rt_entry = sr_find_rt_entry(sr, ip_hdr->ip_dst);
  if (!rt_entry) {
    fprintf(stderr, "No route to host for ICMP Echo Reply\n");
    free(icmp_reply);
    return;
  }

  struct sr_if *out_iface = sr_get_interface(sr, rt_entry->interface);
  if (!out_iface) {
    fprintf(stderr, "Failed to get outgoing interface\n");
    free(icmp_reply);
    return;
  }

  // Check ARP cache
  uint32_t next_hop_ip =
      (rt_entry->gw.s_addr != 0) ? rt_entry->gw.s_addr : ip_hdr->ip_dst;
  struct sr_arpentry *arp_entry = sr_arpcache_lookup(&sr->cache, next_hop_ip);

  if (arp_entry) {
    memcpy(eth_hdr->ether_shost, out_iface->addr, ETHER_ADDR_LEN);
    memcpy(eth_hdr->ether_dhost, arp_entry->mac, ETHER_ADDR_LEN);
    sr_send_packet(sr, icmp_reply, len, out_iface->name);
    free(arp_entry);
    free(icmp_reply);
  } else {
    struct sr_arpreq *req = sr_arpcache_queuereq(
        &sr->cache, next_hop_ip, icmp_reply, len, out_iface->name);
    handle_arpreq(sr, req);
  }
}




/* Add any additional helper methods here & don't forget to also declare
them in sr_router.h.

If you use any of these methods in sr_arpcache.c, you must also forward declare
them in sr_arpcache.h to avoid circular dependencies. Since sr_router
already imports sr_arpcache.h, sr_arpcache cannot import sr_router.h -KM */