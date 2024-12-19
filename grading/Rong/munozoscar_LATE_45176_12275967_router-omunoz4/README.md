# README for Assignment 2: Router

Name: Oscar Munoz

JHED: omunoz4

---

**DESCRIBE YOUR CODE AND DESIGN DECISIONS HERE**

This will be worth 10% of the assignment grade.

Some guiding questions:
- What files did you modify (and why)?

I just modified the sr_arpcache.c and the sr_router.c for the main implementation, however, I also added some extra outpuot on the vns_comm.c while debugging to output the interface for debugging purposes since interfaces would mismatch and it helped understadn more and improve on the code structure in sr_router.c as I implemented and tested. 


- What helper method did you write (and why)?

I broke down the code into two main big helper functions, handle ip and handle icmp packets, as these would be the main cases that had to be handled from the handle packets function, from there I created a helper functions that would be called within these two functions, such as handle_arp_packet, create_icmp_packet, send_icmp_packet, handle_icmp_packet, and long_prefix_match.


- What logic did you implement in each file/method?

sr_arpcache.c:

I mainly followed the logic in the comments on the header file, which had pseudocode provided to implement the two missing functions. 

sr_arpcache_sweepreqs- Thsi function just iterates over the requests on the cache, the handling of whether to keep sending requests or destroy requests is done on the next function

handle_arpreq- sends requests at intervals, if timeouts occur, then send appropiate icmp error, the unreachable host error is sent from here

sr_router.c :

handle_packet
I received the incoming packet, and immediately breakdown the header, to fully see what's incoming and clearly pass it along the other functions to ensure proper handling. Call handle_ip_packets or handle_arp_packets, similar structure to the tutorial.

handle_ip_packets-
This function handles ip packets, the implementation closely follows the description of it on the readme and the presentation. Essentially checks if ip belongs to router by checking its interface, if it is then it manages the ping request. Handles port unreachable if its udp/tcp packet. Lastly it forwards the packet by calling the send_ip function. 

send_ip_packet - This handles the forwaring packets to the next hop ip, based on the routing table. Uses long prefix match, if a match/route is indetified then get the next hop ip and its interface for the packets. Looks up arp entry for next hop to update the ethernet ehader with the appropiate mac address to send the packet. If no arp entry existss, then ptu the packet on the queue to send arp requests to get the MAC address. If not route is found, then it just sends network unreachable icmp error. 

long_prefix_match- mainly implement the long_prefix_match ,retunr best match route for the ip on the routing table for the next_hop. 

create_icpm_packet - Creates ICMP packets closely following the hints provided, does so for replies adn error messages. 

send_icpm_packet - Almost a wrapper function, but mostly just to increase readability as I debugged, this function calls create icmp packet with proper parameters and thne sends the created packet by calling send_packet.

handle_arp_packet - This function handles Arp packets, requests and replies, using the headers to see what type of arp packet it is. For requests, all it checks if interface is on the router, then it sends a reply to send MAC for given ip address. Handles replies by putting them on the cache and sending packets waiting for the mac address based on the cache. 

send_arp_packet - This helper function creates and sends arp requests based on the information given. Follows closely the hints to create the packets based on replies and requests. Handles mac address resolution based on given parameters 

- What problems or challenges did you encounter?

At first, I wasn't "decomposing" the packet on arrival, I was decomposing it on every method as needed and trying to pass the ip, interface on every function, which made my code hard to understand and follow as I finished coding. I managed to finish implementing this way but when testing all the packets were dropped on every command, and none of the functions worked. Overall the logic looked fine, however when adding the print statements on vns_comm.c and using some debugging methods provided to see the state of the arp cache and packet headers, the main issue was mismatch in interfaces and assingning src adn dst addresses wrong, which was very confusing given my initial code structure. When I started getting seg faults, I decided to "soft restart", and decompose the packets on arrival, getting the source and destination ip, as well as the interface, adn the header adn passing those along as the program progressed on to every helper function, restarting this way allowed me to carefully build and handle the packages correctly, as when testing the basic commands started working, since the packet building was essentially given from the google doc, I just had to ensure I was building them with the correct information from the incoming packets to send them correctly. After this, I mainly used some of the responses on piazza which gave me clues to fixing some other minor issues, such as extra hops on traceroute due to sligth mishandling of TTL as well as testing for unreachable host, which i tested by adding an entry of a nonexistent ip to eth1. 
