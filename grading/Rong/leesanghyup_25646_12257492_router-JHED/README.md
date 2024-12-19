# README for Assignment 2: Router

Name: Sanghyup Lee  

JHED: slee548



## Modified Files

`sr_router.c` - This main file includes core packet-handling functions, particularly in the `sr_handlepacket` function. Multiple helper functions were added to enhance packet processing.

`sr_arpcache.c` - This file implements `sr_arpcache_sweepreqs` and `handle_arpreq`, two essential components for handling the ARP cache efficiently.

These files were essential for implementing the router simulation, allowing it to handle ARP and IP packets successfully.

## Helper Functions Created

### sr_router.c
**sr_send_arp_reply**  
This function constructs and sends an ARP reply packet in response to an ARP request directed at the router. It builds the Ethernet and ARP headers, setting the source and destination MAC and IP addresses appropriately, then transmits the reply packet to the requesting host.

**sr_send_arp_request**  
This function constructs and sends an ARP request packet to resolve the MAC address for a specified target IP address. It builds the Ethernet and ARP headers, setting the sender's MAC and IP in the request, with a broadcast MAC address for the target, and then transmits the packet.

**count_leading_ones**  
Counts the number of leading ones in a given 32-bit integer mask by left-shifting the mask bit-by-bit until the most significant bit is zero, tallying each leading one encountered.

**sr_find_rt_entry**  
Searches the router's routing table for the best matching route for a given destination IP address. It applies the subnet mask for each entry to find the longest matching prefix and returns the routing table entry with the longest match, if any.

**calculate_checksum**  
This function verifies the checksum of an IP header to ensure data integrity. It temporarily sets the checksum field to zero, computes the checksum, then restores the original checksum value. If the calculated checksum does not match the original, it logs an error and returns false.

**forward_packet**  
Forwards a packet by updating its Ethernet header with the destination MAC address and the source MAC address of the outgoing interface. It then sends the packet out on the specified interface.

**send_icmp_message**  
Constructs and sends an ICMP message in response to network errors (such as "Destination Unreachable" or "Time Exceeded") encountered by the router. It builds Ethernet, IP, and ICMP headers for the ICMP error message, and sends it to the originating host or queues it for an ARP request if the next hop is unknown.

**send_icmp_echo_reply**  
Constructs and sends an ICMP Echo Reply packet in response to an ICMP Echo Request (ping) received by the router. It prepares the Ethernet, IP, and ICMP headers, updating fields to reflect the response, and either sends the reply immediately if the next-hop MAC address is known or queues the packet while waiting for ARP resolution.

### sr_arpcache.c
**sr_arpcache_sweepreqs**  
Iterates through all pending ARP requests in the ARP cache, calling `handle_arpreq` on each to either retransmit the ARP request or handle timeouts and cleanup for requests that have failed after repeated attempts.

**handle_arpreq**  
Handles an ARP request by either retransmitting the ARP request if a response has not been received or by sending ICMP "Host Unreachable" messages to queued packets waiting on the request if the request has timed out. After five unsuccessful ARP requests, the function clears the request and notifies all dependent packets of failure.

## Logic
I followed the steps within a2_tutorial.pdf, implementing the conditional statements outlined to achieve the final code.

1. Iterate through the ARP Cache and handle all pending ARP requests.
2. Check Ethernet Header  
   - If Ethernet Type is IP:
     - Calculate checksum. If correct, proceed.
     - If destination IP is in Interface:
       - If ICMP Packet:
         - If ICMP Type is 8:
           - Send ICMP echo request.
         - Else, ignore ICMP packet.
       - Else, send ICMP Port Unreachable.
     - Else, prepare for port forwarding:
       - Decrement TTL and recalculate checksum.
       - If TTL = 0, send ICMP expired.
       - Find Best entry. If none:
         - Send ICMP message.
       - Else, get the next hop IP address.
         - Look up ARP cache. If found:
           - Forward packet and free cache entry.
         - Else, enqueue ARP request and handle it.
   - If Ethernet Type is ARP:
     - If ARP request:
       - Get Interface.
       - If exists, send ARP reply; else, drop request.
     - If ARP Reply:
       - Cache ARP reply.
       - If there is a waiting request:
         - Send queued packets and remove request.

## Problems
I initially encountered issues with ARP Cache logic, specifically in providing a proper ICMP response for IP addresses listed in the routing table but not in the IP configuration. Implementing request sweeping resolved this issue by allowing the router to send appropriate ICMP messages to the client.
