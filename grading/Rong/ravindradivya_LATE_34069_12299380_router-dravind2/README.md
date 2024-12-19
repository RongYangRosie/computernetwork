# README for Assignment 2: Router

Name: Divya Ravindra

JHED: dravind2

---

**DESCRIBE YOUR CODE AND DESIGN DECISIONS HERE**

This will be worth 10% of the assignment grade.

Some guiding questions:
- What files did you modify (and why)?
I modified the sr_router.c file and the sr_arpcache.c file. The purpose of the assignment is to create a router and those were the two files that I needed to modify to send a packet down the rt table given and handle different scenarios.

- What helper method did you write (and why)?

This router implementation handles both ARP and IP packet processing through its main entry point sr_handlepacket. For ARP packets, it processes requests by sending appropriate replies and handles replies by updating its ARP cache and forwarding any queued packets. For IP packets, it first validates headers and checksums, then determines if the packet is destined for the router itself or needs forwarding. If the packet is for the router, it handles ICMP echo requests (pings) with appropriate replies, and generates ICMP error messages for unsupported protocols (TCP/UDP) or unreachable destinations. For packets requiring forwarding, it decrements the TTL, updates checksums, determines the outgoing interface through longest-prefix matching in the routing table, and either forwards the packet immediately if the destination MAC is known or queues it while sending an ARP request. The code includes  error handling, thread-safe ARP cache operations, and helper functions for packet manipulation and validation, as well as header construction and checksum calculations for all outgoing packets.
The implementation has basic routing: forward_ip_packet for packet forwarding, validate_packet_headers for integrity checks, handle_arp_reply for ARP cache management, dest_iface for routing decisions, icmp_echo and icmp_err for ICMP message generation, and various ARP-related functions (send_arp_request, send_arp_reply) for handling address resolution.

- What logic did you implement in each file/method?
I've organized this router with sr_handlepacket as the main entry point where all packet processing begins. This method checks if packets are valid and figures out if they're ARP or IP packets, then sends them to the right handler. When checking packets, I use validate_packet_headers to make sure they're the right length, have the correct ethernet type, and for IP packets, that their checksum is valid.
For IP packets, handle_ip_packet takes care of anything meant for the router itself. It checks if it's ICMP, TCP, or UDP and handles it accordingly or sends back a "port unreachable" message when needed. I've set up several ICMP methods: icmp_echo creates ping responses, icmp_err generates error messages, and handle_icmp_echo_request deals with ping requests.
The ARP methods handle address resolution: send_arp_reply creates responses when other devices ask for MAC addresses, send_arp_request asks other devices for their MAC addresses, and handle_arp_reply updates the ARP cache and sends any packets that were waiting for the address.
For routing, dest_iface finds the best match in the routing table, while forward_ip_packet and forward_packet handle sending packets to their next destination with updated headers.
I've kept the code organized by separating different functions - validation, processing, and error handling each have their own space. Everything's broken down into helper functions to keep it manageable. I've also made sure to handle memory properly and keep things thread-safe, especially when dealing with shared resources like the ARP cache. Each method checks its inputs and handles errors, which helps prevent crashes when dealing with broken or unusual packets.

- What problems or challenges did you encounter?
The main problem that I faced was with dealing with arp requests; for a while, I would lose the first few packets that I'd send to an address that was within my network (unknown MAC); I was having trouble handling that. This was happening in the forward section of my ip condition in the main sr_handle_packet() function. This was due to improper thread handling & i was able to resolve this issue. Another issue I dealt with initially was not properly organizing my code in the sense where I had a lot of logic in one function and it was harder to isolate specific issues and resolve them- ended up creating many more helpers.

