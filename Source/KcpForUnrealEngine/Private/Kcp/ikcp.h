#ifndef IKCP_H
#define IKCP_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define IKCP_RTO_NDL 30
#define IKCP_RTO_MIN 100
#define IKCP_RTO_DEF 200
#define IKCP_RTO_MAX 60000

#define IKCP_CMD_PUSH 81
#define IKCP_CMD_ACK  82
#define IKCP_CMD_WASK 83
#define IKCP_CMD_WINS 84

#define IKCP_ASK_SEND 1
#define IKCP_ASK_TELL 2

#define IKCP_WND_SND 32
#define IKCP_WND_RCV 32
#define IKCP_MTU_DEF 1400
#define IKCP_ACK_FAST 3
#define IKCP_INTERVAL 100
#define IKCP_OVERHEAD 24
#define IKCP_DEADLINK 20
#define IKCP_THRESH_INIT 2
#define IKCP_THRESH_MIN 2
#define IKCP_PROBE_INIT 7000
#define IKCP_PROBE_LIMIT 120000

#define IKCP_LOG_OUTPUT 1
#define IKCP_LOG_INPUT 2
#define IKCP_LOG_SEND 4
#define IKCP_LOG_RECV 8
#define IKCP_LOG_IN_DATA 16
#define IKCP_LOG_IN_ACK 32
#define IKCP_LOG_IN_PROBE 64
#define IKCP_LOG_IN_WINS 128
#define IKCP_LOG_OUT_DATA 256
#define IKCP_LOG_OUT_ACK 512
#define IKCP_LOG_OUT_PROBE 1024
#define IKCP_LOG_OUT_WINS 2048

struct IKCPCB;

typedef int (*ikcpcb_output)(const char* buf, int len, struct IKCPCB* kcp, void* user);

struct IKCPSEG
{
    struct IKCPSEG* next;
    uint32_t conv;
    uint32_t cmd;
    uint32_t frg;
    uint32_t wnd;
    uint32_t ts;
    uint32_t sn;
    uint32_t una;
    uint32_t len;
    uint32_t resendts;
    uint32_t rto;
    uint32_t fastack;
    uint32_t xmit;
    char data[1];
};

struct IKCPCB
{
    uint32_t conv;
    uint32_t mtu;
    uint32_t mss;
    uint32_t state;
    uint32_t snd_una;
    uint32_t snd_nxt;
    uint32_t rcv_nxt;
    uint32_t ts_recent;
    uint32_t ts_lastack;
    uint32_t ssthresh;
    int rx_rttval;
    int rx_srtt;
    int rx_rto;
    int rx_minrto;
    uint32_t snd_wnd;
    uint32_t rcv_wnd;
    uint32_t rmt_wnd;
    uint32_t cwnd;
    uint32_t probe;
    uint32_t current;
    uint32_t interval;
    uint32_t ts_flush;
    uint32_t xmit;
    uint32_t nrcv_buf;
    uint32_t nsnd_buf;
    uint32_t nrcv_que;
    uint32_t nsnd_que;
    uint32_t nodelay;
    uint32_t updated;
    uint32_t ts_probe;
    uint32_t probe_wait;
    uint32_t dead_link;
    uint32_t incr;

    struct IKCPSEG* snd_queue;
    struct IKCPSEG* rcv_queue;
    struct IKCPSEG* snd_buf;
    struct IKCPSEG* rcv_buf;

    uint32_t* acklist;
    uint32_t ackcount;
    uint32_t ackblock;

    char* buffer;
    int fastresend;
    int nocwnd;
    int stream;

    int logmask;
    ikcpcb_output output;
    void* user;
};

struct IKCPCB* ikcp_create(uint32_t conv, void* user);
void ikcp_release(struct IKCPCB* kcp);
void ikcp_setoutput(struct IKCPCB* kcp, ikcpcb_output output);

int ikcp_recv(struct IKCPCB* kcp, char* buffer, int len);
int ikcp_send(struct IKCPCB* kcp, const char* buffer, int len);
void ikcp_update(struct IKCPCB* kcp, uint32_t current);
uint32_t ikcp_check(const struct IKCPCB* kcp, uint32_t current);
int ikcp_input(struct IKCPCB* kcp, const char* data, long size);

void ikcp_flush(struct IKCPCB* kcp);
int ikcp_peeksize(const struct IKCPCB* kcp);
int ikcp_setmtu(struct IKCPCB* kcp, int mtu);
int ikcp_wndsize(struct IKCPCB* kcp, int sndwnd, int rcvwnd);
int ikcp_waitsnd(const struct IKCPCB* kcp);
int ikcp_nodelay(struct IKCPCB* kcp, int nodelay, int interval, int resend, int nc);

#ifdef __cplusplus
}
#endif

#endif
