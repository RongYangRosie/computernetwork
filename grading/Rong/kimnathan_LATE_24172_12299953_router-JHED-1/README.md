# README for Assignment 2: Router

Name:

JHED:

---

**DESCRIBE YOUR CODE AND DESIGN DECISIONS HERE**

This will be worth 10% of the assignment grade.

Some guiding questions:
- What files did you modify (and why)?
- What helper method did you write (and why)?
- What logic did you implement in each file/method?
- What problems or challenges did you encounter?

# Router Implementation

The first thing I did was implement the arp cache, so that my router would be able to find other hosts' mac addresses. This was in `sr_arpcache.*`

First, I wrote `handle_arpreq()`
- I followed the pseudocode for my control logic
- ICMP error packets go from the router's interface to the original sender
- ARP Requests go from the router's interface to broadcast `0xff`

I wrote helper function `sr_lookup_route()` to find routing table entry

I wrote `sr_arpcache_sweepreqs()`
- Followed the pseudocode in the header file

Then I wrote in `sr_router.*`
- First, I wrote the control code, as specified by the tutorial.

Then I started with `sr_handle_arprequest`
- This part is meant to say "I'm the router, I have that IP and here's my MAC address", so it sends back to the requesting device the router's information.

Then I wrote `sr_handle_arpreply`
- This part is meant to say "Here are all the packets meant for you", so it loops through all the packets of the request and sends them off to the one that replied.

If the packet type is not an ARP request, then check its checksum and size.

If the packet is meant for the router, then call `sr_destined_for_router`
- Determine if it's an echo or not, and store that result in variable 'echo'. The length of the ICMP packet will differ based on the result. 
- I followed the tutorial to know how and when to send an ICMP type 3 code 3, and type 0 code 0.

Otherwise, it's for IP forwarding.
- I prepare an error packet to send either ICMP 3 or ICMP 11, using my helper function `icmp_3_error()` and `icmp_11_error()`.
- The code will return if there was an error. Otherwise, it reaches the part of my code that checks if an ARP entry exists for the next hop IP and MAC address.

If it exists, it gets forwarded using `forward_packet()`

Otherwise, I call `handle_arpreq()`, which will broadcast ARP Requests to `0xff`, as stated before, or it will time out in the queue, after being requested 5 times.
