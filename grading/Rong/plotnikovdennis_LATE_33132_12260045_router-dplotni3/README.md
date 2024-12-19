# README for Assignment 2: Router

Name: Dennis Plotnikov

JHED: dplotni3

---

**DESCRIBE YOUR CODE AND DESIGN DECISIONS HERE**

This will be worth 10% of the assignment grade.

**Checklist of tests on my end**

In my testing all tests have passed based on the requirements of the assignment description.

- Ping from client to server1: ✔ Ping replies in reasonable amount of time

- Ping from client to server2: ✔ Likewise replies in reasonable amt of ms

- Ping from client to eth1: ✔ Ping quickly replies, although from a different interface's IP than the target (assignment description says this is okay)

- Ping from client to eth2: ✔ Likewise, ping quickly replies, although from a different interface IP than the target (assignment description says this is okay)

- Ping from client to eth3: ✔ Ping replies with same IP as target

- Traceroute from client to server1: ✔ Makes it in 6 hops, both the router and dest are listed

- Traceroute from client to server2: ✔ Likewise makes it in ~6 hops, and both the router IP and dest IP are listed

- Traceroute from client to eth1: ✔ Correctly lists only IP of eth3 interface, since that is the actual interface the route is traced through 

- Traceroute from client to eth2: ✔ Likewise correctly lists only IP of eth3 interface, since that is the actual interface the route is traced through

- Traceroute from client to eth3: ✔ Correctly lists only IP of eth3

- Get HTTP content from server1: ✔ wget works without issue

- Get HTTP content from server2: ✔ wget works without issue

- Send a ping from client to server with TTL=1 (router should
reject with TTL exceeded): ✔ ping is consistently replied with a timeout message

- Send a ping from client to destination IP not in routing table
(router should reject with “destination Net Unreachable): ✔ Ping returns net unreachable message each time

- Send a ping from client to a destination IP that is in routing
table, but does not exist (router return Destination Host
Unreachable): ✔ After 5 seconds (thus allowing all 5 possible ARP requests to be sent and fail), all ping messages are returned with destination host unreachable

- README: Description of Code you wrote: ✔ Here I am!

---

Some guiding questions:
- What files did you modify (and why)?

I modified only the source and header files for sr_arpcache, and sr_router. 

- What helper method did you write (and why)?
- What logic did you implement in each file/method?

I wrote 7 helper methods in sr_router, and 2 in sr_arpcache. 

My logic goes as follows:

> sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet,
        unsigned int len,
        char* interface) 

In the sr_handlepacket method (for which a skeleton was given to start with), we check the packet by protocol type. If it is an ARP packet, we check its destination IP against the interface's IP, and drop the packet if they do not match (since that would indicate that the ARP request has been sent in error). If the ARP packet is a request, we send it to the "reply_to_request" helper method. If it is a reply, we add its data to the cache, and then send out any packets waiting on it via the "send_to_all_waiting" helper method. 

If the packet is an IP packet, we check its dest address against all the interface IP's of the router. If it does not match any, the packet is forwarded via the "forward_ip_packet" helper method. If it does match, it is intended for us, and so we deal with it in the "parse_ip_packet" helper method. This handles all cases that we need our code to handle.

> reply_to_request (struct sr_instance *sr, struct sr_ethernet_hdr *incoming_ethernet_header, char *interface)

In this helper function, we create a new packet for an ARP reply. we fill the ethernet header and ARP header with all the correct flags to indicate this as a reply, and set the destination address to be the source of the request, so as to send this reply back to the requestor. We fill the ARP's target IP with the source IP of the request, and the source IP with the IP of the interface. This allows the ARP request to actually fill in the cache of the requestor by associating the IP to the MAC address of the interface. The packet is then sent, and the memory freed.

> send_to_all_waiting (struct sr_instance *sr, struct sr_arpreq *arp_request, struct sr_arp_hdr *arp_header)

In this function, I iterate through all packets in the "packets" linked list in the arp_request struct (given by the addition to the cache entry in "sr_handlepacket"). For each one, the respective ethernet headers are modified to use our newly received routing data, allowing us to then send it out to the correct MAC address via the correct interface. The interface to send to is found via the "route_ip_packet" helper function. 

> forward_ip_packet (struct sr_instance *sr, uint8_t *packet, unsigned int len, char *interface)

In this function, I first get the IP header of the packet, and check the TTL. If it is 1 or below, I send back a type 11 ICMP error via the "send_icmp_packet" helper method, since this packet is now timed out. I then decrement the TTL of the packet (updating the checksum in the process), and attempt to get a route for the packet with the "route_ip_packet" helper. If no route is found, an ICMP error type 3 code 0 is sent back to the incoming interface. Otherwise, we continue with finding the next hop MAC address with an arpcache lookup. If we find it, we send the IP packet with the "send_out_ip_packet" helper. Otherwise, we add this packet to the queue and send out an arp request.

> parse_ip_packet (struct sr_instance *sr, uint8_t *packet, unsigned int len, char *interface)

In this function, we get our IP header, and first check its checksum to ensure the packet is coherent. Then, we check the protocol of the packet. If it is not ICMP, we immediately send an ICMP type 3 code 3 error back via "send_icmp_packet", since we only support ICMP. Next, we check if the packet is an ICMP echo request. If not, we drop the packet, and if it is, then we send an echo reply of ICMP type 0 code 0.

> struct sr_rt *route_ip_packet (struct sr_instance *sr, uint8_t *packet)

In this function, we iterate through the routing table to find the longest prefix match. For each entry in the table linked list, we check if the address matches the dest address of the incoming packet, up to the mask. Then, we store this if the mask is longer than the previous best candidate. We then either return the match, or NULL if we have exhausted the list.

> send_out_ip_packet (struct sr_instance *sr, uint8_t *packet, unsigned int len, char *interface, struct sr_arpentry *arp_entry)

We create a new IP packet, and fill it from the incoming packet. Then, this packet is modified by changing the ethernet source to be the outgoing interface, and dest to be the MAC address we found from the ARP cache. We then send the packet.

> send_icmp_packet (struct sr_instance *sr, uint8_t *packet, unsigned int len, char *interface, uint8_t type, uint8_t code)

We first get the headers of the incoming packet to which this is a response to, and allocate a new packet. If this is an echo reply, we allocate it to the same length as the incoming, otherwise we allocate it to the length of the header structs added. For an echo reply, we then simply copy the entire ICMP part of the incoming packet into the ICMP of the response packet. Otherwise, we copy the incoming IP header and the first 8 bytes of the IP body of the incoming packet into the ICMP body of the new packet. 

Then, we set the type and code based on what kind of message this is, and compute the ICMP checksum. Then, we build up the IP header with the proper flags and values for this packet to be sent out, with the dest IP being gotten from the source IP of the incoming packet, and the source IP as the IP of the interface that got this packet (the assignment description implies that this should be okay even for pings directed to a different interface of the router). Finally, the ethernet header is built so as to send to the MAC address of the source of the incoming packet, from the MAC of the interface that got that packet. The packet is then sent off.

> handle_arpreq(struct sr_instance *sr, struct sr_arpreq *request)

We check the system time, and see if the last time the request was sent was more than 1 second ago. If so, we proceed. If the request has already been sent 5 times and yet is still in the queue, we call this a failure, and call the "arp_failure" helper function. Otherwise, we send an ARP request via "arp_send" helper function, and update the time and number of times sent accordingly.

> arp_send (struct sr_instance *sr, uint32_t target_ip)

We send (to all interfaces to ensure receipt) an ARP request. We build an ARP packet, setting the ethernet flags appropriately and setting the ARP flags and values to indicate a request. We then send it off. 

> arp_failure (struct sr_instance *sr, struct sr_arpreq *request)

We send an ICMP error of type 3 code 1 to the source interfaces of all packets waiting on this request, via the "send_icmp_packet" helper function.

> sr_arpcache_sweepreqs(struct sr_instance *sr)

We implement this function by just iterating through everything in the linked list of requestsin the cache, and calling the "handle_arpreq" function on each.

---

- What problems or challenges did you encounter?

There were many problems I encountered along the way, which required a large amount of time to debug (and I am glad I started this assignment early, since it ended up taking me past the deadline to fully debug).

First, I had an issue where no ARP packets were sending properly at all. This ended up being an issue with how I was handling conversion between network and host order. In particular, I did not at first understand that the IP addresses were already in network order - so no conversion at all was needed for either comparing against them, nor sending them back out. Once I added all appropriate htons(), and removed the extraneous htonl I had for the IP's, the ARP requrests began to work.

Next, there was a problem with getting packets to forward correctly. After combing through, the issue ended up being with how I was getting entries from the queue, as I misunderstood how one of the structs worked. After that was resolved, packets forwarded fine.

Next, there was an issue with getting ICMP packets to send. At first I combed through the code for the actual sending and the headers, but the issue ended up being the body of the ICMP packet. For echo, I did not correctly allocate the requisite amount of memory to handle all the body of the message, while for non-echo ICMP replies, I did not correctly move the top 8 bytes of the original IP header into the ICMP body (I only realized this upon reading up on the real-world documentation for ICMP replies for errors). After this was corrected, ICMP replies were functional, as were pings.

Finally, there was some confusion regarding how to correctly deal with the interface of packets on the queue. Since the "packet" struct of the queue only has one interface data point, I had to find a way to include data about both the source interface (for sending ICMP error if host unreachable) and about the destination interface. I settled in the end on just checking the routing table when sending packets off the queue (slightly redundant but not a big issue), and using the packet->iface for storing the source interface for errors.

After those challenges were resolved, the code passed every check in the tutorial slides.