#include "ikcp.h"

#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdio.h>

#ifndef IKCP_MAX
#define IKCP_MAX(a, b) ((a) > (b) ? (a) : (b))
#endif

#ifndef IKCP_MIN
#define IKCP_MIN(a, b) ((a) <= (b) ? (a) : (b))
#endif

#ifndef IKCP_BOUND
#define IKCP_BOUND(lower, middle, upper) IKCP_MIN(IKCP_MAX(lower, middle), upper)
#endif

static inline uint32_t _itimediff(uint32_t later, uint32_t earlier)
{
    return (int32_t)(later - earlier);
}

static inline uint32_t _encode32u(char* p, uint32_t l)
{
    p[0] = (char)(l >> 0);
    p[1] = (char)(l >> 8);
    p[2] = (char)(l >> 16);
    p[3] = (char)(l >> 24);
    return 4;
}

static inline uint32_t _decode32u(const char* p)
{
    return ((uint32_t)(unsigned char)p[0]) | ((uint32_t)(unsigned char)p[1] << 8) |
        ((uint32_t)(unsigned char)p[2] << 16) | ((uint32_t)(unsigned char)p[3] << 24);
}

static inline char* _encode_seg(char* ptr, const struct IKCPSEG* seg)
{
    ptr += _encode32u(ptr, seg->conv);
    ptr += _encode32u(ptr, seg->cmd);
    ptr += _encode32u(ptr, seg->frg);
    ptr += _encode32u(ptr, seg->wnd);
    ptr += _encode32u(ptr, seg->ts);
    ptr += _encode32u(ptr, seg->sn);
    ptr += _encode32u(ptr, seg->una);
    ptr += _encode32u(ptr, seg->len);
    return ptr;
}

static inline int _decode_seg(const char* ptr, struct IKCPSEG* seg)
{
    seg->conv = _decode32u(ptr);
    seg->cmd = _decode32u(ptr + 4);
    seg->frg = _decode32u(ptr + 8);
    seg->wnd = _decode32u(ptr + 12);
    seg->ts = _decode32u(ptr + 16);
    seg->sn = _decode32u(ptr + 20);
    seg->una = _decode32u(ptr + 24);
    seg->len = _decode32u(ptr + 28);
    return 0;
}

static inline int _ikcp_log(const struct IKCPCB* kcp, int mask, const char* fmt, ...)
{
    if ((mask & kcp->logmask) == 0)
    {
        return 0;
    }

    va_list args;
    va_start(args, fmt);
    vprintf(fmt, args);
    va_end(args);
    return 0;
}

static inline struct IKCPSEG* _seg_new(int size)
{
    struct IKCPSEG* seg = (struct IKCPSEG*)malloc(sizeof(struct IKCPSEG) + size);
    if (seg)
    {
        memset(seg, 0, sizeof(struct IKCPSEG));
    }
    return seg;
}

static inline void _seg_del(struct IKCPSEG* seg)
{
    free(seg);
}

static void _seg_qpush(struct IKCPSEG* newseg, struct IKCPSEG** head)
{
    struct IKCPSEG* seg = *head;
    if (!seg)
    {
        *head = newseg;
        newseg->next = nullptr;
    }
    else
    {
        while (seg->next)
        {
            seg = seg->next;
        }
        seg->next = newseg;
        newseg->next = nullptr;
    }
}

static struct IKCPSEG* _seg_qpop(struct IKCPSEG** head)
{
    struct IKCPSEG* seg = *head;
    if (seg)
    {
        *head = seg->next;
        seg->next = nullptr;
    }
    return seg;
}

static void _ikcp_free(void* ptr)
{
    if (ptr)
    {
        free(ptr);
    }
}

static void* _ikcp_malloc(size_t size)
{
    return malloc(size);
}

static void ikcp_update_ack(struct IKCPCB* kcp, int rtt);
static void ikcp_shrink_buf(struct IKCPCB* kcp);
static void ikcp_parse_ack(struct IKCPCB* kcp, uint32_t sn);
static void ikcp_parse_una(struct IKCPCB* kcp, uint32_t una);
static void ikcp_parse_fastack(struct IKCPCB* kcp, uint32_t sn);
static void ikcp_ack_push(struct IKCPCB* kcp, uint32_t sn, uint32_t ts);
static void ikcp_parse_data(struct IKCPCB* kcp, struct IKCPSEG* newseg);

struct IKCPCB* ikcp_create(uint32_t conv, void* user)
{
    struct IKCPCB* kcp = (struct IKCPCB*)_ikcp_malloc(sizeof(struct IKCPCB));
    if (!kcp)
    {
        return nullptr;
    }

    memset(kcp, 0, sizeof(*kcp));
    kcp->conv = conv;
    kcp->user = user;
    kcp->snd_wnd = IKCP_WND_SND;
    kcp->rcv_wnd = IKCP_WND_RCV;
    kcp->rmt_wnd = IKCP_WND_RCV;
    kcp->mtu = IKCP_MTU_DEF;
    kcp->mss = kcp->mtu - IKCP_OVERHEAD;
    kcp->rx_rto = IKCP_RTO_DEF;
    kcp->rx_minrto = IKCP_RTO_MIN;
    kcp->interval = IKCP_INTERVAL;
    kcp->ts_flush = IKCP_INTERVAL;
    kcp->ssthresh = IKCP_THRESH_INIT;
    kcp->dead_link = IKCP_DEADLINK;
    kcp->buffer = (char*)_ikcp_malloc((kcp->mtu + IKCP_OVERHEAD) * 3);
    if (!kcp->buffer)
    {
        ikcp_release(kcp);
        return nullptr;
    }
    return kcp;
}

void ikcp_release(struct IKCPCB* kcp)
{
    struct IKCPSEG* seg = nullptr;
    while ((seg = _seg_qpop(&kcp->snd_buf)) != nullptr)
    {
        _seg_del(seg);
    }
    while ((seg = _seg_qpop(&kcp->rcv_buf)) != nullptr)
    {
        _seg_del(seg);
    }
    while ((seg = _seg_qpop(&kcp->snd_queue)) != nullptr)
    {
        _seg_del(seg);
    }
    while ((seg = _seg_qpop(&kcp->rcv_queue)) != nullptr)
    {
        _seg_del(seg);
    }

    _ikcp_free(kcp->buffer);
    _ikcp_free(kcp->acklist);
    _ikcp_free(kcp);
}

void ikcp_setoutput(struct IKCPCB* kcp, ikcpcb_output output)
{
    kcp->output = output;
}

int ikcp_recv(struct IKCPCB* kcp, char* buffer, int len)
{
    struct IKCPSEG* seg;
    int ispeek = (len < 0) ? 1 : 0;
    if (len < 0)
    {
        len = -len;
    }

    if (kcp->nrcv_que == 0)
    {
        return -1;
    }

    if (len < 0)
    {
        return -2;
    }

    int peeksize = ikcp_peeksize(kcp);
    if (peeksize < 0)
    {
        return -3;
    }

    if (peeksize > len)
    {
        return -2;
    }

    int recover = kcp->nrcv_que >= kcp->rcv_wnd;
    int fragment = 0;
    int count = 0;
    int received = 0;
    while ((seg = kcp->rcv_queue) != nullptr)
    {
        if (len < (int)seg->len)
        {
            break;
        }

        _seg_qpop(&kcp->rcv_queue);
        if (!ispeek)
        {
            memcpy(buffer, seg->data, seg->len);
            buffer += seg->len;
        }
        len -= seg->len;
        received += seg->len;
        fragment = seg->frg;
        _seg_del(seg);
        kcp->nrcv_que--;
        count++;

        if (fragment == 0)
        {
            break;
        }
    }

    while (kcp->rcv_buf && kcp->rcv_buf->sn == kcp->rcv_nxt && kcp->nrcv_que < kcp->rcv_wnd)
    {
        seg = _seg_qpop(&kcp->rcv_buf);
        kcp->nrcv_buf--;
        _seg_qpush(seg, &kcp->rcv_queue);
        kcp->nrcv_que++;
        kcp->rcv_nxt++;
    }

    if (kcp->nrcv_que < kcp->rcv_wnd && recover)
    {
        kcp->probe |= IKCP_ASK_TELL;
    }

    return received;
}

int ikcp_send(struct IKCPCB* kcp, const char* buffer, int len)
{
    if (len < 0)
    {
        return -1;
    }

    int count = 0;
    if (len <= (int)kcp->mss)
    {
        count = 1;
    }
    else
    {
        count = (len + kcp->mss - 1) / kcp->mss;
    }

    if (count > 255)
    {
        return -2;
    }

    if (count == 0)
    {
        count = 1;
    }

    for (int i = 0; i < count; i++)
    {
        int size = len > (int)kcp->mss ? kcp->mss : len;
        struct IKCPSEG* seg = _seg_new(size);
        if (!seg)
        {
            return -3;
        }
        if (buffer && len > 0)
        {
            memcpy(seg->data, buffer, size);
        }
        seg->len = size;
        seg->frg = (uint32_t)(count - i - 1);
        _seg_qpush(seg, &kcp->snd_queue);
        kcp->nsnd_que++;
        if (buffer)
        {
            buffer += size;
        }
        len -= size;
    }

    return 0;
}

void ikcp_update(struct IKCPCB* kcp, uint32_t current)
{
    kcp->current = current;

    if (!kcp->updated)
    {
        kcp->updated = 1;
        kcp->ts_flush = kcp->current;
    }

    int32_t slap = _itimediff(kcp->current, kcp->ts_flush);
    if (slap >= 10000 || slap < -10000)
    {
        kcp->ts_flush = kcp->current;
        slap = 0;
    }

    if (slap >= 0)
    {
        kcp->ts_flush += kcp->interval;
        if (_itimediff(kcp->current, kcp->ts_flush) >= 0)
        {
            kcp->ts_flush = kcp->current + kcp->interval;
        }
        ikcp_flush(kcp);
    }
}

uint32_t ikcp_check(const struct IKCPCB* kcp, uint32_t current)
{
    uint32_t ts_flush = kcp->ts_flush;
    int32_t tm_flush = 0x7fffffff;
    int32_t tm_packet = 0x7fffffff;
    if (!kcp->updated)
    {
        return current;
    }

    if (_itimediff(current, ts_flush) >= 10000 || _itimediff(current, ts_flush) < -10000)
    {
        ts_flush = current;
    }

    if (_itimediff(current, ts_flush) >= 0)
    {
        return current;
    }

    tm_flush = _itimediff(ts_flush, current);

    struct IKCPSEG* seg = kcp->snd_buf;
    while (seg)
    {
        int32_t diff = _itimediff(seg->resendts, current);
        if (diff <= 0)
        {
            return current;
        }
        if (diff < tm_packet)
        {
            tm_packet = diff;
        }
        seg = seg->next;
    }

    int32_t minimal = tm_packet < tm_flush ? tm_packet : tm_flush;
    if (minimal >= (int32_t)kcp->interval)
    {
        minimal = kcp->interval;
    }

    return current + minimal;
}

int ikcp_input(struct IKCPCB* kcp, const char* data, long size)
{
    if (!data || size < IKCP_OVERHEAD)
    {
        return -1;
    }

    uint32_t prev_una = kcp->snd_una;
    uint32_t maxack = 0;
    int flag = 0;

    while (size >= IKCP_OVERHEAD)
    {
        struct IKCPSEG* seg = nullptr;
        uint32_t conv = _decode32u(data);
        if (conv != kcp->conv)
        {
            return -1;
        }

        uint32_t cmd = _decode32u(data + 4);
        uint32_t frg = _decode32u(data + 8);
        uint32_t wnd = _decode32u(data + 12);
        uint32_t ts = _decode32u(data + 16);
        uint32_t sn = _decode32u(data + 20);
        uint32_t una = _decode32u(data + 24);
        uint32_t len = _decode32u(data + 28);

        data += IKCP_OVERHEAD;
        size -= IKCP_OVERHEAD;

        if (size < (long)len)
        {
            return -2;
        }

        if (cmd != IKCP_CMD_PUSH && cmd != IKCP_CMD_ACK && cmd != IKCP_CMD_WASK && cmd != IKCP_CMD_WINS)
        {
            return -3;
        }

        kcp->rmt_wnd = wnd;
        ikcp_parse_una(kcp, una);
        ikcp_shrink_buf(kcp);

        if (cmd == IKCP_CMD_ACK)
        {
            ikcp_update_ack(kcp, _itimediff(kcp->current, ts));
            ikcp_parse_ack(kcp, sn);
            ikcp_shrink_buf(kcp);
            if (!flag)
            {
                flag = 1;
                maxack = sn;
            }
            else if (_itimediff(sn, maxack) > 0)
            {
                maxack = sn;
            }
        }
        else if (cmd == IKCP_CMD_PUSH)
        {
            if (_itimediff(sn, kcp->rcv_nxt + kcp->rcv_wnd) < 0)
            {
                ikcp_ack_push(kcp, sn, ts);
                if (_itimediff(sn, kcp->rcv_nxt) >= 0)
                {
                    seg = _seg_new(len);
                    if (!seg)
                    {
                        return -4;
                    }

                    seg->conv = conv;
                    seg->cmd = cmd;
                    seg->frg = frg;
                    seg->wnd = wnd;
                    seg->ts = ts;
                    seg->sn = sn;
                    seg->una = una;
                    seg->len = len;

                    if (len > 0)
                    {
                        memcpy(seg->data, data, len);
                    }
                    ikcp_parse_data(kcp, seg);
                }
            }
        }
        else if (cmd == IKCP_CMD_WASK)
        {
            kcp->probe |= IKCP_ASK_TELL;
        }
        else if (cmd == IKCP_CMD_WINS)
        {
            // Nothing to do
        }

        data += len;
        size -= len;
    }

    if (flag)
    {
        ikcp_parse_fastack(kcp, maxack);
    }

    if (_itimediff(kcp->snd_una, prev_una) > 0)
    {
        if (kcp->cwnd < kcp->rmt_wnd)
        {
            if (kcp->cwnd < kcp->ssthresh)
            {
                kcp->cwnd++;
                kcp->incr += kcp->mss;
            }
            else
            {
                if (kcp->incr < kcp->mss)
                {
                    kcp->incr = kcp->mss;
                }
                kcp->incr += (kcp->mss * kcp->mss) / kcp->incr + (kcp->mss / 16);
                if ((kcp->cwnd + 1) * kcp->mss <= kcp->incr)
                {
                    kcp->cwnd++;
                }
            }
            if (kcp->cwnd > kcp->rmt_wnd)
            {
                kcp->cwnd = kcp->rmt_wnd;
                kcp->incr = kcp->rmt_wnd * kcp->mss;
            }
        }
    }

    return 0;
}

int ikcp_peeksize(const struct IKCPCB* kcp)
{
    if (kcp->nrcv_que == 0)
    {
        return -1;
    }

    struct IKCPSEG* seg = kcp->rcv_queue;
    if (seg->frg == 0)
    {
        return seg->len;
    }

    if (kcp->nrcv_que < seg->frg + 1)
    {
        return -1;
    }

    int length = 0;
    while (seg)
    {
        length += seg->len;
        if (seg->frg == 0)
        {
            break;
        }
        seg = seg->next;
    }

    return length;
}

int ikcp_setmtu(struct IKCPCB* kcp, int mtu)
{
    if (mtu < 50 || mtu < IKCP_OVERHEAD)
    {
        return -1;
    }

    kcp->mtu = mtu;
    kcp->mss = kcp->mtu - IKCP_OVERHEAD;

    _ikcp_free(kcp->buffer);
    kcp->buffer = (char*)_ikcp_malloc((kcp->mtu + IKCP_OVERHEAD) * 3);
    if (!kcp->buffer)
    {
        return -2;
    }

    return 0;
}

int ikcp_wndsize(struct IKCPCB* kcp, int sndwnd, int rcvwnd)
{
    if (sndwnd > 0)
    {
        kcp->snd_wnd = sndwnd;
    }
    if (rcvwnd > 0)
    {
        kcp->rcv_wnd = rcvwnd;
    }
    return 0;
}

int ikcp_waitsnd(const struct IKCPCB* kcp)
{
    return kcp->nsnd_buf + kcp->nsnd_que;
}

int ikcp_nodelay(struct IKCPCB* kcp, int nodelay, int interval, int resend, int nc)
{
    if (nodelay >= 0)
    {
        kcp->nodelay = nodelay;
        if (nodelay)
        {
            kcp->rx_minrto = IKCP_RTO_NDL;
        }
        else
        {
            kcp->rx_minrto = IKCP_RTO_MIN;
        }
    }

    if (interval >= 0)
    {
        kcp->interval = IKCP_BOUND(10, interval, 5000);
    }

    if (resend >= 0)
    {
        kcp->fastresend = resend;
    }

    if (nc >= 0)
    {
        kcp->nocwnd = nc;
    }

    return 0;
}

void ikcp_flush(struct IKCPCB* kcp)
{
    char* buffer = kcp->buffer;
    char* ptr = buffer;
    int count = 0;
    if (!kcp->updated)
    {
        return;
    }

    struct IKCPSEG seg;
    memset(&seg, 0, sizeof(seg));
    seg.conv = kcp->conv;
    seg.cmd = IKCP_CMD_ACK;
    seg.wnd = kcp->rcv_wnd;
    seg.una = kcp->rcv_nxt;

    for (uint32_t i = 0; i < kcp->ackcount; i++)
    {
        if (ptr - buffer + IKCP_OVERHEAD > (int)kcp->mtu)
        {
            kcp->output(buffer, (int)(ptr - buffer), kcp, kcp->user);
            ptr = buffer;
        }
        seg.sn = kcp->acklist[i * 2 + 0];
        seg.ts = kcp->acklist[i * 2 + 1];
        ptr = _encode_seg(ptr, &seg);
    }
    kcp->ackcount = 0;

    if (kcp->rmt_wnd == 0)
    {
        if (kcp->probe_wait == 0)
        {
            kcp->probe_wait = IKCP_PROBE_INIT;
            kcp->ts_probe = kcp->current + kcp->probe_wait;
        }
        else
        {
            if (_itimediff(kcp->current, kcp->ts_probe) >= 0)
            {
                if (kcp->probe_wait < IKCP_PROBE_INIT)
                {
                    kcp->probe_wait = IKCP_PROBE_INIT;
                }
                kcp->probe_wait += kcp->probe_wait / 2;
                if (kcp->probe_wait > IKCP_PROBE_LIMIT)
                {
                    kcp->probe_wait = IKCP_PROBE_LIMIT;
                }
                kcp->ts_probe = kcp->current + kcp->probe_wait;
                kcp->probe |= IKCP_ASK_SEND;
            }
        }
    }
    else
    {
        kcp->ts_probe = 0;
        kcp->probe_wait = 0;
    }

    if (kcp->probe & IKCP_ASK_SEND)
    {
        seg.cmd = IKCP_CMD_WASK;
        if (ptr - buffer + IKCP_OVERHEAD > (int)kcp->mtu)
        {
            kcp->output(buffer, (int)(ptr - buffer), kcp, kcp->user);
            ptr = buffer;
        }
        ptr = _encode_seg(ptr, &seg);
    }

    if (kcp->probe & IKCP_ASK_TELL)
    {
        seg.cmd = IKCP_CMD_WINS;
        if (ptr - buffer + IKCP_OVERHEAD > (int)kcp->mtu)
        {
            kcp->output(buffer, (int)(ptr - buffer), kcp, kcp->user);
            ptr = buffer;
        }
        ptr = _encode_seg(ptr, &seg);
    }

    kcp->probe = 0;

    int cwnd = IKCP_MIN(kcp->snd_wnd, kcp->rmt_wnd);
    if (!kcp->nocwnd)
    {
        cwnd = IKCP_MIN(kcp->cwnd, cwnd);
    }

    while (_itimediff(kcp->snd_nxt, kcp->snd_una + cwnd) < 0)
    {
        struct IKCPSEG* newseg = _seg_qpop(&kcp->snd_queue);
        if (!newseg)
        {
            break;
        }

        newseg->conv = kcp->conv;
        newseg->cmd = IKCP_CMD_PUSH;
        newseg->wnd = seg.wnd;
        newseg->ts = kcp->current;
        newseg->sn = kcp->snd_nxt++;
        newseg->una = kcp->rcv_nxt;
        newseg->resendts = kcp->current;
        newseg->rto = kcp->rx_rto;
        newseg->fastack = 0;
        newseg->xmit = 0;

        _seg_qpush(newseg, &kcp->snd_buf);
        kcp->nsnd_buf++;
        kcp->nsnd_que--;
    }

    uint32_t resent = (kcp->fastresend > 0) ? kcp->fastresend : 0xffffffff;
    uint32_t rtomin = (kcp->nodelay == 0) ? (uint32_t)kcp->rx_rto >> 3 : 0;

    for (struct IKCPSEG* segp = kcp->snd_buf; segp; segp = segp->next)
    {
        int needsend = 0;
        if (segp->xmit == 0)
        {
            needsend = 1;
            segp->xmit++;
            segp->rto = kcp->rx_rto;
            segp->resendts = kcp->current + segp->rto + rtomin;
        }
        else if (_itimediff(kcp->current, segp->resendts) >= 0)
        {
            needsend = 1;
            segp->xmit++;
            kcp->xmit++;
            if (kcp->nodelay == 0)
            {
                segp->rto += IKCP_MAX(segp->rto, kcp->rx_rto);
            }
            else
            {
                segp->rto += kcp->rx_rto / 2;
            }
            segp->resendts = kcp->current + segp->rto;
        }
        else if (segp->fastack >= resent)
        {
            needsend = 1;
            segp->xmit++;
            segp->fastack = 0;
            segp->resendts = kcp->current + segp->rto;
        }

        if (needsend)
        {
            segp->ts = kcp->current;
            segp->wnd = seg.wnd;
            segp->una = kcp->rcv_nxt;

            int need = IKCP_OVERHEAD + segp->len;
            if (ptr - buffer + need > (int)kcp->mtu)
            {
                kcp->output(buffer, (int)(ptr - buffer), kcp, kcp->user);
                ptr = buffer;
            }

            ptr = _encode_seg(ptr, segp);
            if (segp->len > 0)
            {
                memcpy(ptr, segp->data, segp->len);
                ptr += segp->len;
            }

            if (segp->xmit >= kcp->dead_link)
            {
                kcp->state = 0xFFFFFFFF;
            }
        }
    }

    if (ptr != buffer)
    {
        kcp->output(buffer, (int)(ptr - buffer), kcp, kcp->user);
    }
}

// Helper functions for input processing
static void ikcp_update_ack(struct IKCPCB* kcp, int rtt)
{
    if (kcp->rx_srtt == 0)
    {
        kcp->rx_srtt = rtt;
        kcp->rx_rttval = rtt / 2;
    }
    else
    {
        int delta = rtt - kcp->rx_srtt;
        if (delta < 0)
        {
            delta = -delta;
        }
        kcp->rx_rttval = (3 * kcp->rx_rttval + delta) / 4;
        kcp->rx_srtt = (7 * kcp->rx_srtt + rtt) / 8;
        if (kcp->rx_srtt < 1)
        {
            kcp->rx_srtt = 1;
        }
    }

    int rto = kcp->rx_srtt + IKCP_MAX(kcp->interval, 4 * kcp->rx_rttval);
    kcp->rx_rto = IKCP_BOUND(kcp->rx_minrto, rto, IKCP_RTO_MAX);
}

static void ikcp_shrink_buf(struct IKCPCB* kcp)
{
    struct IKCPSEG* seg = kcp->snd_buf;
    if (seg)
    {
        kcp->snd_una = seg->sn;
    }
    else
    {
        kcp->snd_una = kcp->snd_nxt;
    }
}

static void ikcp_parse_ack(struct IKCPCB* kcp, uint32_t sn)
{
    if (_itimediff(sn, kcp->snd_una) < 0 || _itimediff(sn, kcp->snd_nxt) >= 0)
    {
        return;
    }

    struct IKCPSEG* seg = kcp->snd_buf;
    struct IKCPSEG* prev = nullptr;
    while (seg)
    {
        if (sn == seg->sn)
        {
            if (prev)
            {
                prev->next = seg->next;
            }
            else
            {
                kcp->snd_buf = seg->next;
            }
            _seg_del(seg);
            kcp->nsnd_buf--;
            break;
        }
        if (_itimediff(sn, seg->sn) < 0)
        {
            break;
        }
        prev = seg;
        seg = seg->next;
    }
}

static void ikcp_parse_una(struct IKCPCB* kcp, uint32_t una)
{
    struct IKCPSEG* seg = kcp->snd_buf;
    while (seg)
    {
        if (_itimediff(una, seg->sn) > 0)
        {
            struct IKCPSEG* next = seg->next;
            _seg_del(seg);
            kcp->nsnd_buf--;
            seg = next;
            kcp->snd_buf = seg;
        }
        else
        {
            break;
        }
    }
}

static void ikcp_parse_fastack(struct IKCPCB* kcp, uint32_t sn)
{
    if (_itimediff(sn, kcp->snd_una) < 0 || _itimediff(sn, kcp->snd_nxt) >= 0)
    {
        return;
    }

    struct IKCPSEG* seg = kcp->snd_buf;
    while (seg)
    {
        if (_itimediff(sn, seg->sn) < 0)
        {
            break;
        }
        else if (sn != seg->sn)
        {
            seg->fastack++;
        }
        seg = seg->next;
    }
}

static void ikcp_ack_push(struct IKCPCB* kcp, uint32_t sn, uint32_t ts)
{
    uint32_t newsize = kcp->ackcount + 1;
    if (newsize > kcp->ackblock)
    {
        uint32_t newblock = kcp->ackblock ? kcp->ackblock * 2 : 8;
        uint32_t* acklist = (uint32_t*)_ikcp_malloc(newblock * 2 * sizeof(uint32_t));
        if (!acklist)
        {
            return;
        }
        if (kcp->acklist)
        {
            memcpy(acklist, kcp->acklist, kcp->ackcount * 2 * sizeof(uint32_t));
            _ikcp_free(kcp->acklist);
        }
        kcp->acklist = acklist;
        kcp->ackblock = newblock;
    }

    kcp->acklist[kcp->ackcount * 2 + 0] = sn;
    kcp->acklist[kcp->ackcount * 2 + 1] = ts;
    kcp->ackcount++;
}

static void ikcp_parse_data(struct IKCPCB* kcp, struct IKCPSEG* newseg)
{
    uint32_t sn = newseg->sn;
    struct IKCPSEG* seg = kcp->rcv_buf;
    struct IKCPSEG* prev = nullptr;
    int repeat = 0;

    if (_itimediff(sn, kcp->rcv_nxt + kcp->rcv_wnd) >= 0 || _itimediff(sn, kcp->rcv_nxt) < 0)
    {
        _seg_del(newseg);
        return;
    }

    while (seg)
    {
        if (seg->sn == sn)
        {
            repeat = 1;
            break;
        }
        if (_itimediff(sn, seg->sn) < 0)
        {
            break;
        }
        prev = seg;
        seg = seg->next;
    }

    if (!repeat)
    {
        if (!prev)
        {
            newseg->next = kcp->rcv_buf;
            kcp->rcv_buf = newseg;
        }
        else
        {
            newseg->next = prev->next;
            prev->next = newseg;
        }
        kcp->nrcv_buf++;
    }
    else
    {
        _seg_del(newseg);
    }

    while (kcp->rcv_buf && kcp->rcv_buf->sn == kcp->rcv_nxt && kcp->nrcv_que < kcp->rcv_wnd)
    {
        seg = _seg_qpop(&kcp->rcv_buf);
        kcp->nrcv_buf--;
        _seg_qpush(seg, &kcp->rcv_queue);
        kcp->nrcv_que++;
        kcp->rcv_nxt++;
    }
}
