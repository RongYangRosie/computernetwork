/*
 * transport.c 
 *
 * EN.601.414/614: HW#3 (STCP)
 *
 * This file implements the STCP layer that sits between the
 * mysocket and network layers. You are required to fill in the STCP
 * functionality in this file. 
 *
 */


#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include "mysock.h"
#include "stcp_api.h"
#include "transport.h"
#include <arpa/inet.h>

enum { 
    CSTATE_ESTABLISHED,
    CSTATE_FIN_WAIT_1,
    CSTATE_FIN_WAIT_2,
    CSTATE_LAST_ACK,
    CSTATE_CLOSED

};    /* obviously you should have more states */

typedef struct window_t
{
    void * payload;
    window_t* next_entry;
    tcp_seq ack_expected;
    tcp_seq seq_num;
    unsigned int time_sent;
} window_t;

/* this structure is global to a mysocket descriptor */
typedef struct
{
    bool_t done;    /* TRUE once connection is closed */

    int connection_state;   /* state of the connection (established, etc.) */
    tcp_seq initial_sequence_num;
    tcp_seq peer_initial_sequence_num;
    /* any other connection-wide global variables go here */
    tcp_seq last_byte_acked; // last acked received
    tcp_seq last_byte_sent; // next unsent seq num
    unsigned int advertised_size;
    window_t* snd_wnd;

    /* receive window stuff */
    tcp_seq next_byte_expected; // last frame received
    tcp_seq last_byte_recvd; // first unack'd frame

} context_t;

const unsigned int WINDOW_SIZE = 3072;

int min(int a, int b) {
  return (a < b ? a : b);
}

/* sends syn packet */
int send_syn(mysocket_t sd, context_t* ctx) {
    // construct packet
    STCPHeader* syn_packet = (STCPHeader*) malloc(sizeof(STCPHeader));
    syn_packet->th_seq = htonl(ctx->initial_sequence_num);
    syn_packet->th_ack = htonl(ctx->initial_sequence_num + 1); // next expected seq number
    syn_packet->th_off = 5;
    syn_packet->th_flags = TH_SYN;
    printf("\treceived a packet\n");

    // send packet
    syn_packet->th_win = htons(WINDOW_SIZE);
    ssize_t send_len = stcp_network_send(sd, syn_packet, sizeof(STCPHeader), NULL);
    ctx->last_byte_sent = ctx->initial_sequence_num;
    free(syn_packet);
    return send_len;
}

/* waits for syn packet */
int wait_syn(mysocket_t sd, context_t* ctx) {
    void* buffer[sizeof(STCPHeader) + STCP_MSS];
    size_t len = stcp_network_recv(sd, buffer, STCP_MSS + sizeof(STCPHeader));
    printf("\treceived a packet\n");
    STCPHeader* syn_hdr = (STCPHeader*) buffer;
    if (len > 0 && (syn_hdr->th_flags & TH_SYN) != 0x0) {

        // received syn packet
        ctx->peer_initial_sequence_num = ntohl(syn_hdr->th_seq);
        ctx->last_byte_recvd = ntohl(syn_hdr->th_seq);
        ctx->next_byte_expected = ntohl(syn_hdr->th_seq) + 1;
        ctx->advertised_size = ntohs(syn_hdr->th_win);

    }
    return len;
}

/* sends syn packet */
int send_syn_ack(mysocket_t sd, context_t* ctx) {
    // construct packet
    STCPHeader* syn_packet = (STCPHeader*) malloc(sizeof(STCPHeader));
    syn_packet->th_seq = htonl(ctx->initial_sequence_num);
    syn_packet->th_ack = htonl(ctx->next_byte_expected);
    syn_packet->th_off = 5;
    syn_packet->th_flags = TH_SYN | TH_ACK;
    syn_packet->th_win =  htons(WINDOW_SIZE - (ctx->next_byte_expected - ctx->last_byte_recvd));

    // send packet
    size_t len = stcp_network_send(sd, syn_packet, sizeof(STCPHeader), NULL);
    ctx->last_byte_sent = ctx->initial_sequence_num;
    free(syn_packet);
    return len;
}

/* waits for syn packet */
int wait_syn_ack(mysocket_t sd, context_t* ctx) {
    void* buffer[sizeof(STCPHeader) + STCP_MSS];
    size_t len = stcp_network_recv(sd, buffer, STCP_MSS + sizeof(STCPHeader));
    STCPHeader* syn_hdr = (STCPHeader*) buffer;
    if (len > 0 && (syn_hdr->th_flags & (TH_SYN | TH_ACK)) != 0x0) {
        // sync receiver's initial seq number
        ctx->peer_initial_sequence_num = ntohl(syn_hdr->th_seq);

        // store latest ack receieved
        ctx->last_byte_acked = ntohl(syn_hdr->th_ack) - 1;

        // store last frame received
        ctx->next_byte_expected = ntohl(syn_hdr->th_seq) + 1;
        ctx->last_byte_recvd = ntohl(syn_hdr->th_seq);
        ctx->advertised_size = ntohs(syn_hdr->th_win);

    }
    return len;
}

/* sends ack packet */
int send_ack(mysocket_t sd, context_t* ctx) {

    // construct packet
    STCPHeader* ack_pkt = (STCPHeader*) malloc(sizeof(STCPHeader));
    ack_pkt->th_seq = htonl(ctx->last_byte_sent + 1);
    ack_pkt->th_ack = htonl(ctx->next_byte_expected);
    ack_pkt->th_off = 5;
    ack_pkt->th_flags =TH_ACK;
    ack_pkt->th_win = htons(WINDOW_SIZE - (ctx->next_byte_expected - ctx->last_byte_recvd));
    // ack_pkt->th_win = htons(100);

    // send packet and free
    size_t len = stcp_network_send(sd, ack_pkt, sizeof(STCPHeader), NULL);
    if (len) {
        printf("\tack sent %d\n", ntohl(ack_pkt->th_ack) - ctx->peer_initial_sequence_num);
    }
    free(ack_pkt);
    return len;
}

/* waits for final ack packet in handshake */
int wait_ack(mysocket_t sd, context_t* ctx) {
    void* buffer[sizeof(STCPHeader) + STCP_MSS];
    size_t len = stcp_network_recv(sd, buffer, STCP_MSS + sizeof(STCPHeader));
    STCPHeader* syn_hdr = (STCPHeader*) buffer;
    if (len > 0 && (syn_hdr->th_flags & TH_ACK) != 0x0) {
        // store latest ack receieved
        ctx->last_byte_acked = ntohl(syn_hdr->th_ack) - 1;

        // End handshake
        ctx->advertised_size = ntohs(syn_hdr->th_win);
    }
    return len;
}

/* takes a packet with data field already filled in, sends pkt through network */
size_t send_net_pkt(mysocket_t sd, context_t* ctx, void * pkt, size_t data_len) {
    STCPHeader* net_pkt = (STCPHeader*) pkt;
    net_pkt->th_seq = htonl(ctx->last_byte_sent + 1);
    net_pkt->th_off = 5;
    net_pkt->th_ack = htonl(ctx->next_byte_expected);
    net_pkt->th_win = htons(WINDOW_SIZE - (ctx->next_byte_expected - ctx->last_byte_recvd));

    size_t len = stcp_network_send(sd, net_pkt, sizeof(STCPHeader) + data_len, NULL);
    // len = stcp_network_send(sd, net_pkt, sizeof(STCPHeader) + data_len, NULL);
    printf("\t sent net packet data len %d with seq num: %d\n", (int) data_len, ntohl(net_pkt->th_seq) - ctx->initial_sequence_num);
    free(net_pkt);
    return len;
}

size_t send_fin(mysocket_t sd, context_t* ctx, tcp_seq seq_num) {
    STCPHeader * fin_pkt = (STCPHeader*) malloc(sizeof(STCPHeader));
    memset(fin_pkt, 0, sizeof(STCPHeader));
    fin_pkt->th_flags = TH_FIN;
    fin_pkt->th_seq = htonl(seq_num);
    fin_pkt->th_ack = htonl(ctx->next_byte_expected);
    fin_pkt->th_win = htons(WINDOW_SIZE - (ctx->next_byte_expected - ctx->last_byte_recvd));
    fin_pkt->th_off = 5;
    printf("\tflag: %d\n", fin_pkt->th_flags);
    size_t len = stcp_network_send(sd, fin_pkt, sizeof(STCPHeader), NULL);
    ctx->last_byte_sent++;
    printf("\tfin sent seq num %d\n", htonl(fin_pkt->th_seq) - ctx->initial_sequence_num);
    free(fin_pkt);
    return len;
}

void handle_app_data(mysocket_t sd, context_t* ctx) {
    size_t max_pkt_len = min(ctx->advertised_size - (ctx->last_byte_sent - ctx->last_byte_acked), STCP_MSS);
    // if no room in window, just don't take any app data
    if (max_pkt_len <= 0) {
        return;
    }

    void * buffer = malloc(sizeof(STCPHeader) + max_pkt_len);
    memset(buffer, 0, sizeof(STCPHeader) + max_pkt_len);
    size_t data_len = stcp_app_recv(sd, (void*) ((char*) buffer + sizeof(STCPHeader)), max_pkt_len);
    printf("\tdata_len: %d\n", (int)data_len);
    if (send_net_pkt(sd, ctx, buffer, data_len) <= 0) {
        perror("failed to send packet through network");
    } else {
        ctx->last_byte_sent += data_len;

    }
}
void handle_network_pkt(mysocket_t sd, context_t* ctx, void * pkt, ssize_t pkt_len) {
    STCPHeader * stcp_hdr = (STCPHeader*)pkt;
    printf("\tflag: %d, seq num: %d\n", stcp_hdr->th_flags, ntohl(stcp_hdr->th_seq) - ctx->peer_initial_sequence_num);
    if (stcp_hdr->th_flags & TH_ACK) {
        // handle ack
        if (ctx->connection_state == CSTATE_ESTABLISHED) {
            if (ntohl(stcp_hdr->th_ack) > ctx->last_byte_acked + 1) {
                ctx->last_byte_acked = ntohl(stcp_hdr->th_ack) - 1;
                ctx->advertised_size = ntohs(stcp_hdr->th_win);
            }
        } else if (ctx->connection_state == CSTATE_FIN_WAIT_1) {
            ctx->last_byte_acked = ntohl(stcp_hdr->th_ack) - 1;
            ctx->last_byte_recvd = ntohl(stcp_hdr->th_seq);
            ctx->connection_state = CSTATE_FIN_WAIT_2;

        } else if (ctx->connection_state == CSTATE_LAST_ACK) {
            printf("\t closing server connection state\n");
            ctx->connection_state = CSTATE_CLOSED;
            ctx->done = TRUE;
            ctx->last_byte_acked = ntohl(stcp_hdr->th_ack) - 1;
        }

        printf("\tack received, last byte acked: %d\n", ctx->last_byte_acked - ctx->initial_sequence_num);
    }
    if ((stcp_hdr->th_flags & TH_FIN)) {
        printf("\tfin packet received\n");
        ctx->last_byte_recvd = ntohl(stcp_hdr->th_seq); // special case since fin pkt technically has no data
        ctx->next_byte_expected = ctx->last_byte_recvd + 1;
        if (ctx->connection_state == CSTATE_ESTABLISHED) {

            // send ack
            send_ack(sd, ctx);

            // send fin
            send_fin(sd, ctx, ctx->last_byte_sent + 1);
            ctx->connection_state = CSTATE_LAST_ACK;
        } else if (ctx->connection_state == CSTATE_FIN_WAIT_2) {
            printf("\t closing client connection state\n");
            send_ack(sd, ctx);
            ctx->connection_state = CSTATE_CLOSED;
            ctx->done = TRUE;

        }

    }
    if (pkt_len > (ssize_t)sizeof(STCPHeader)) {
        // handle data received
        printf("\tdata packet received seq num: %d\n", ntohl(stcp_hdr->th_seq) - ctx->peer_initial_sequence_num);
        printf("\tExpected Seq num: %d\n", ctx->next_byte_expected - ctx->peer_initial_sequence_num);
        if (ntohl(stcp_hdr->th_seq) != ctx->next_byte_expected) {
            printf("\t unexpected seqnum\n");
        fflush(stdout);

        }

        // only send data not received yet.
        if (ntohl(stcp_hdr->th_seq) + pkt_len - sizeof(STCPHeader) - 1 > ctx->last_byte_recvd) {
            printf("\t not duplicate\n");
            // if (pkt_len - sizeof(STCPHeader) > 100) {
            //     printf("error: received packet too large\n");
            // }
            stcp_app_send(sd, (void*)((char*) pkt + sizeof(STCPHeader)), pkt_len - sizeof(STCPHeader));
            ctx->last_byte_recvd = ntohl(stcp_hdr->th_seq) + pkt_len - sizeof(STCPHeader) - 1;
            ctx->next_byte_expected = ctx->last_byte_recvd + 1;
            send_ack(sd, ctx);
        } else {
            // duplicate data
            printf("\t duplicate detected\n");
            fflush(stdout);
            send_ack(sd, ctx);
        }

    }
}

static void generate_initial_seq_num(context_t *ctx);
static void control_loop(mysocket_t sd, context_t *ctx);


/* initialise the transport layer, and start the main loop, handling
 * any data from the peer or the application.  this function should not
 * return until the connection is closed.
 */
void transport_init(mysocket_t sd, bool_t is_active)
{
    context_t *ctx;

    ctx = (context_t *) calloc(1, sizeof(context_t));
    assert(ctx);

    generate_initial_seq_num(ctx);
    ctx->last_byte_acked = ctx->initial_sequence_num;
    /* XXX: you should send a SYN packet here if is_active, or wait for one
     * to arrive if !is_active.  after the handshake completes, unblock the
     * application with stcp_unblock_application(sd).  you may also use
     * this to communicate an error condition back to the application, e.g.
     * if connection fails; to do so, just set errno appropriately (e.g. to
     * ECONNREFUSED, etc.) before calling the function.
     */
    printf("handshake:\n");
    if (is_active) {
        // send syn packet
        if (send_syn(sd, ctx) <= 0) {
            perror("error: failed to send syn packet\n");
            return;
        }
        printf("\thandshake sent syn\n");

        // wait for syn ack
        if (wait_syn_ack(sd, ctx) <= 0) {

            perror("error: failed to receive syn ack\n");
            return;
        }
        printf("\thandshake syn ack received\n");

        // send ack
        if (!send_ack(sd, ctx)) {
            perror("error: failed to send first ack\n");
            return;
        }
        printf("client handshake finished...\n");
        fflush(stdout);
    } else {
        // wait for syn
        if (wait_syn(sd, ctx) <= 0) {
            perror("error: failed to receive syn packet\n");
            return;
        }
        printf("\thandshake syn received\n");

        // send syn ack
        if (send_syn_ack(sd, ctx) <= 0) {
            perror("error: failed to send syn ack\n");
        }
        printf("\thandshake syn ack sent\n");

        // wait for ack
        if (wait_ack(sd, ctx) <= 0) {
            perror("error: cannot receive final ack in handshake\n");
        }
        printf("\thandshake last ack received\n");
        fprintf(stdout, "\tserver handshake finished...\n");
        fflush(stdout);

    }
    ctx->connection_state = CSTATE_ESTABLISHED;
    printf("\tlast byte sent: %d\n", ctx->last_byte_sent - ctx->initial_sequence_num);
    printf("\tlast byte acked: %d\n", ctx->last_byte_acked - ctx->initial_sequence_num);
    printf("\tnext byte expected: %d\n", ctx->next_byte_expected - ctx->peer_initial_sequence_num);
    printf("\tlast byte received: %d\n", ctx->last_byte_recvd - ctx->peer_initial_sequence_num);
    printf("\tadvertised window: %d\n",ctx->advertised_size);

    stcp_unblock_application(sd);

    control_loop(sd, ctx);

    /* do any cleanup here */
    free(ctx);
}


/* generate random initial sequence number for an STCP connection */
static void generate_initial_seq_num(context_t *ctx)
{
    assert(ctx);

#ifdef FIXED_INITNUM
    /* please don't change this! */
    ctx->initial_sequence_num = 1;
#else
    /* you have to fill this up */
    ctx->initial_sequence_num = rand() % 255;
#endif
}


/* control_loop() is the main STCP loop; it repeatedly waits for one of the
 * following to happen:
 *   - incoming data from the peer
 *   - new data from the application (via mywrite())
 *   - the socket to be closed (via myclose())
 *   - a timeout
 */
static void control_loop(mysocket_t sd, context_t *ctx)
{
    assert(ctx);

    while (!ctx->done)
    {
        /* see stcp_api.h or stcp_api.c for details of this function */
        /* XXX: you will need to change some of these arguments! */

        // TODO: replace NULL with timeout.
        unsigned int event = stcp_wait_for_event(sd, ANY_EVENT, NULL);


        /* check whether it was the network, app, or a close request */
        if (event & APP_DATA)
        {
            printf("app data event, %d\n", ctx->connection_state);
            /* the application has requested that data be sent */
            /* see stcp_app_recv() */
            handle_app_data(sd, ctx);

        }

        if (event & NETWORK_DATA) {
            printf("network data event, %d\n", ctx->connection_state);
            /* received data from network layer */
            void * buffer = malloc(sizeof(STCPHeader) + STCP_MSS);
            ssize_t len_recvd = stcp_network_recv(sd, buffer, sizeof(STCPHeader) + STCP_MSS);
            if (len_recvd < (ssize_t)sizeof(STCPHeader)) {
                // not a valid STCP packet
                return;
            }

            handle_network_pkt(sd, ctx, buffer, len_recvd);
            
        }

        if (event & APP_CLOSE_REQUESTED) {
            /* TCP teardown */
            printf("teardown started, %d\n", ctx->connection_state);
            // send fin
            send_fin(sd, ctx, ctx->last_byte_sent + 1);
            ctx->connection_state = CSTATE_FIN_WAIT_1;
        }

        /* etc. */
    }
    printf("connection ended\n");
    fflush(stdout);

}


/**********************************************************************/
/* our_dprintf
 *
 * Send a formatted message to stdout.
 * 
 * format               A printf-style format string.
 *
 * This function is equivalent to a printf, but may be
 * changed to log errors to a file if desired.
 *
 * Calls to this function are generated by the dprintf amd
 * dperror macros in transport.h
 */
void our_dprintf(const char *format,...)
{
    va_list argptr;
    char buffer[1024];

    assert(format);
    va_start(argptr, format);
    vsnprintf(buffer, sizeof(buffer), format, argptr);
    va_end(argptr);
    fputs(buffer, stdout);
    fflush(stdout);
}



