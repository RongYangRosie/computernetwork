#include <netinet/in.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include <sched.h>
#include <string.h>
#include "sr_arpcache.h"
#include "sr_router.h"
#include "sr_if.h"
#include "sr_protocol.h"
#include "sr_utils.h"

/* Handle an ARP request */
void handle_arpreq(struct sr_instance *sr, struct sr_arpreq *req) {
    time_t now = time(NULL);
    if (difftime(now, req->sent) > 1.0) {
        if (req->times_sent >= 5) {
            /* Send ICMP host unreachable to source addr of all pkts waiting on this req */
            struct sr_packet *pkt;
            for (pkt = req->packets; pkt != NULL; pkt = pkt->next) {
                sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(pkt->buf + sizeof(sr_ethernet_hdr_t));
                struct sr_if *iface = sr_get_interface(sr, pkt->iface);
                
                /* Allocate space for ICMP packet */
                unsigned int len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);
                uint8_t *icmp_packet = (uint8_t *)malloc(len);
                
                /* Fill ethernet header */
                sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)icmp_packet;
                memcpy(eth_hdr->ether_dhost, ((sr_ethernet_hdr_t *)(pkt->buf))->ether_shost, ETHER_ADDR_LEN);
                memcpy(eth_hdr->ether_shost, iface->addr, ETHER_ADDR_LEN);
                eth_hdr->ether_type = htons(ethertype_ip);
                
                /* Fill IP header */
                sr_ip_hdr_t *new_ip_hdr = (sr_ip_hdr_t *)(icmp_packet + sizeof(sr_ethernet_hdr_t));
                new_ip_hdr->ip_v = 4;
                new_ip_hdr->ip_hl = 5;
                new_ip_hdr->ip_tos = 0;
                new_ip_hdr->ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
                new_ip_hdr->ip_id = 0;
                new_ip_hdr->ip_off = htons(IP_DF);
                new_ip_hdr->ip_ttl = INIT_TTL;
                new_ip_hdr->ip_p = ip_protocol_icmp;
                new_ip_hdr->ip_src = iface->ip;
                new_ip_hdr->ip_dst = ip_hdr->ip_src;
                new_ip_hdr->ip_sum = 0;
                new_ip_hdr->ip_sum = cksum(new_ip_hdr, sizeof(sr_ip_hdr_t));
                
                /* Fill ICMP header */
                sr_icmp_t3_hdr_t *icmp_hdr = (sr_icmp_t3_hdr_t *)(icmp_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
                icmp_hdr->icmp_type = 3;
                icmp_hdr->icmp_code = 1;
                icmp_hdr->unused = 0;
                icmp_hdr->next_mtu = 0;
                memcpy(icmp_hdr->data, ip_hdr, ICMP_DATA_SIZE);
                icmp_hdr->icmp_sum = 0;
                icmp_hdr->icmp_sum = cksum(icmp_hdr, sizeof(sr_icmp_t3_hdr_t));
                
                sr_send_packet(sr, icmp_packet, len, pkt->iface);
                free(icmp_packet);
            }
            sr_arpreq_destroy(&(sr->cache), req);
        } else {
            /* Send ARP request */
            struct sr_if *iface = sr_get_interface(sr, req->packets->iface);
            
            /* Create and send ARP request packet */
            unsigned int len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
            uint8_t *arp_packet = (uint8_t *)malloc(len);
            
            /* Fill ethernet header */
            sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)arp_packet;
            memset(eth_hdr->ether_dhost, 0xFF, ETHER_ADDR_LEN);
            memcpy(eth_hdr->ether_shost, iface->addr, ETHER_ADDR_LEN);
            eth_hdr->ether_type = htons(ethertype_arp);
            
            /* Fill ARP header */
            sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *)(arp_packet + sizeof(sr_ethernet_hdr_t));
            arp_hdr->ar_hrd = htons(arp_hrd_ethernet);
            arp_hdr->ar_pro = htons(ethertype_ip);
            arp_hdr->ar_hln = ETHER_ADDR_LEN;
            arp_hdr->ar_pln = 4;
            arp_hdr->ar_op = htons(arp_op_request);
            memcpy(arp_hdr->ar_sha, iface->addr, ETHER_ADDR_LEN);
            arp_hdr->ar_sip = iface->ip;
            memset(arp_hdr->ar_tha, 0, ETHER_ADDR_LEN);
            arp_hdr->ar_tip = req->ip;
            
            sr_send_packet(sr, arp_packet, len, req->packets->iface);
            free(arp_packet);
            
            req->sent = now;
            req->times_sent++;
        }
    }
}


void sr_arpcache_sweepreqs(struct sr_instance *sr) {
    printf("Sweeping ARP requests\n");
    struct sr_arpreq *req = sr->cache.requests;
    while (req != NULL) {
        printf("Processing ARP request for IP: %u\n", req->ip);
        struct sr_arpreq *next_req = req->next;
        handle_arpreq(sr, req);
        req = next_req;
    }
}

/* You should not need to touch the rest of this code. */

/* Checks if an IP->MAC mapping is in the cache. IP is in network byte order.
   You must free the returned structure if it is not NULL. */
struct sr_arpentry *sr_arpcache_lookup(struct sr_arpcache *cache, uint32_t ip) {
    pthread_mutex_lock(&(cache->lock));

    struct sr_arpentry *entry = NULL, *copy = NULL;

    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        if ((cache->entries[i].valid) && (cache->entries[i].ip == ip)) {
            entry = &(cache->entries[i]);
        }
    }

    /* Must return a copy b/c another thread could jump in and modify
       table after we return. */
    if (entry) {
        copy = (struct sr_arpentry *) malloc(sizeof(struct sr_arpentry));
        memcpy(copy, entry, sizeof(struct sr_arpentry));
    }

    pthread_mutex_unlock(&(cache->lock));

    return copy;
}

/* Adds an ARP request to the ARP request queue. If the request is already on
   the queue, adds the packet to the linked list of packets for this sr_arpreq
   that corresponds to this ARP request. You should free the passed *packet.

   A pointer to the ARP request is returned; it should not be freed. The caller
   can remove the ARP request from the queue by calling sr_arpreq_destroy. */
struct sr_arpreq *sr_arpcache_queuereq(struct sr_arpcache *cache,
                                       uint32_t ip,
                                       uint8_t *packet,           /* borrowed */
                                       unsigned int packet_len,
                                       char *iface)
{
    pthread_mutex_lock(&(cache->lock));

    struct sr_arpreq *req;
    for (req = cache->requests; req != NULL; req = req->next) {
        if (req->ip == ip) {
            break;
        }
    }

    /* If the IP wasn't found, add it */
    if (!req) {
        req = (struct sr_arpreq *) calloc(1, sizeof(struct sr_arpreq));
        req->ip = ip;
        req->next = cache->requests;
        cache->requests = req;
    }

    /* Add the packet to the list of packets for this request */
    if (packet && packet_len && iface) {
        struct sr_packet *new_pkt = (struct sr_packet *)malloc(sizeof(struct sr_packet));

        new_pkt->buf = (uint8_t *)malloc(packet_len);
        memcpy(new_pkt->buf, packet, packet_len);
        new_pkt->len = packet_len;
		new_pkt->iface = (char *)malloc(sr_IFACE_NAMELEN);
        strncpy(new_pkt->iface, iface, sr_IFACE_NAMELEN);
        new_pkt->next = req->packets;
        req->packets = new_pkt;
    }

    pthread_mutex_unlock(&(cache->lock));

    return req;
}

/* This method performs two functions:
   1) Looks up this IP in the request queue. If it is found, returns a pointer
      to the sr_arpreq with this IP. Otherwise, returns NULL.
   2) Inserts this IP to MAC mapping in the cache, and marks it valid. */
struct sr_arpreq *sr_arpcache_insert(struct sr_arpcache *cache,
                                     unsigned char *mac,
                                     uint32_t ip)
{
    pthread_mutex_lock(&(cache->lock));

    struct sr_arpreq *req, *prev = NULL, *next = NULL;
    for (req = cache->requests; req != NULL; req = req->next) {
        if (req->ip == ip) {
            if (prev) {
                next = req->next;
                prev->next = next;
            }
            else {
                next = req->next;
                cache->requests = next;
            }

            break;
        }
        prev = req;
    }

    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        if (!(cache->entries[i].valid))
            break;
    }

    if (i != SR_ARPCACHE_SZ) {
        memcpy(cache->entries[i].mac, mac, 6);
        cache->entries[i].ip = ip;
        cache->entries[i].added = time(NULL);
        cache->entries[i].valid = 1;
    }

    pthread_mutex_unlock(&(cache->lock));

    return req;
}

/* Frees all memory associated with this arp request entry. If this arp request
   entry is on the arp request queue, it is removed from the queue. */
void sr_arpreq_destroy(struct sr_arpcache *cache, struct sr_arpreq *entry) {
    pthread_mutex_lock(&(cache->lock));

    if (entry) {
        struct sr_arpreq *req, *prev = NULL, *next = NULL;
        for (req = cache->requests; req != NULL; req = req->next) {
            if (req == entry) {
                if (prev) {
                    next = req->next;
                    prev->next = next;
                }
                else {
                    next = req->next;
                    cache->requests = next;
                }

                break;
            }
            prev = req;
        }

        struct sr_packet *pkt, *nxt;

        for (pkt = entry->packets; pkt; pkt = nxt) {
            nxt = pkt->next;
            if (pkt->buf)
                free(pkt->buf);
            if (pkt->iface)
                free(pkt->iface);
            free(pkt);
        }

        free(entry);
    }

    pthread_mutex_unlock(&(cache->lock));
}

/* Prints out the ARP table. */
void sr_arpcache_dump(struct sr_arpcache *cache) {
    fprintf(stderr, "\nMAC            IP         ADDED                      VALID\n");
    fprintf(stderr, "-----------------------------------------------------------\n");

    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        struct sr_arpentry *cur = &(cache->entries[i]);
        unsigned char *mac = cur->mac;
        fprintf(stderr, "%.1x%.1x%.1x%.1x%.1x%.1x   %.8x   %.24s   %d\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], ntohl(cur->ip), ctime(&(cur->added)), cur->valid);
    }

    fprintf(stderr, "\n");
}

/* Initialize table + table lock. Returns 0 on success. */
int sr_arpcache_init(struct sr_arpcache *cache) {
    /* Seed RNG to kick out a random entry if all entries full. */
    srand(time(NULL));

    /* Invalidate all entries */
    memset(cache->entries, 0, sizeof(cache->entries));
    cache->requests = NULL;

    /* Acquire mutex lock */
    pthread_mutexattr_init(&(cache->attr));
    pthread_mutexattr_settype(&(cache->attr), PTHREAD_MUTEX_RECURSIVE);
    int success = pthread_mutex_init(&(cache->lock), &(cache->attr));

    return success;
}

/* Destroys table + table lock. Returns 0 on success. */
int sr_arpcache_destroy(struct sr_arpcache *cache) {
    return pthread_mutex_destroy(&(cache->lock)) && pthread_mutexattr_destroy(&(cache->attr));
}

/* Thread which sweeps through the cache and invalidates entries that were added
   more than SR_ARPCACHE_TO seconds ago. */
void *sr_arpcache_timeout(void *sr_ptr) {
    struct sr_instance *sr = sr_ptr;
    struct sr_arpcache *cache = &(sr->cache);

    while (1) {
        sleep(1.0);

        pthread_mutex_lock(&(cache->lock));

        time_t curtime = time(NULL);

        int i;
        for (i = 0; i < SR_ARPCACHE_SZ; i++) {
            if ((cache->entries[i].valid) && (difftime(curtime,cache->entries[i].added) > SR_ARPCACHE_TO)) {
                cache->entries[i].valid = 0;
            }
        }

        sr_arpcache_sweepreqs(sr);

        pthread_mutex_unlock(&(cache->lock));
    }

    return NULL;
}
