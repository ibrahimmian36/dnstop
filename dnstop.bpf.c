// SPDX-License-Identifier: GPL-2.0
/*
 * dnstop — kernel-side observer for outbound DNS queries.
 *
 * Hooks udp_sendmsg, filters for destination port 53, and ships the
 * raw DNS payload bytes to userspace. All DNS wire-format parsing,
 * entropy scoring, and DGA/tunneling detection happens in JS where
 * it's testable and iterable. The kernel side just grabs bytes.
 *
 * Two CO-RE hooks (require CONFIG_DEBUG_INFO_BTF + libbpf reloc):
 *   fentry/udp_sendmsg    outbound UDP; we filter dport==53
 *   fentry/tcp_sendmsg    DNS-over-TCP (large responses, zone xfer)
 *
 * Reading the query payload means reading a user buffer out of the
 * msghdr's iov_iter. For a single small DNS packet the iterator is
 * ITER_UBUF (one buffer), so __ubuf_iovec carries base+len. We read
 * that, clamp to DNS_SNAP_LEN, and bpf_probe_read_user the bytes.
 * Vector/multi-buffer sends (not the DNS case) fall back to __iov[0].
 *
 * One RINGBUF (256 KiB) carries dns_evt records.
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

#define AF_INET   2
#define AF_INET6 10
#define DNS_PORT  53
#define DNS_SNAP_LEN 256

char LICENSE[] SEC("license") = "GPL";

/* userspace event */
struct dns_evt {
    __u64 ts_ns;
    __u32 pid;
    __u32 payload_len;       /* bytes actually copied into payload    */
    __u32 msg_len;           /* total size arg to sendmsg             */
    __u16 dport;             /* destination port (host order)         */
    __u8  family;
    __u8  proto;             /* 0 = udp, 1 = tcp                      */
    char  comm[16];
    __u8  payload[DNS_SNAP_LEN];
};

__attribute__((used)) static const struct dns_evt __dns_evt_anchor;

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 18);
} events SEC(".maps");

/* Pull the first user buffer (base + len) out of a msghdr's iov_iter.
 * Returns the base pointer (user address) and writes the length to
 * *out_len. Handles the ITER_UBUF single-buffer case (the DNS norm)
 * and the ITER_IOVEC vector case. Returns NULL if neither resolves. */
static __always_inline const void *
first_iov(struct msghdr *msg, __u64 *out_len) {
    const void *base = NULL;
    __u64 len = 0;

    /* ITER_UBUF: __ubuf_iovec holds the single buffer inline. */
    if (bpf_core_field_exists(msg->msg_iter.__ubuf_iovec)) {
        base = BPF_CORE_READ(msg, msg_iter.__ubuf_iovec.iov_base);
        len  = BPF_CORE_READ(msg, msg_iter.__ubuf_iovec.iov_len);
        if (base) { *out_len = len; return base; }
    }

    /* ITER_IOVEC: __iov points to an array; read element 0. */
    if (bpf_core_field_exists(msg->msg_iter.__iov)) {
        const struct iovec *iov = BPF_CORE_READ(msg, msg_iter.__iov);
        if (iov) {
            base = BPF_CORE_READ(iov, iov_base);
            len  = BPF_CORE_READ(iov, iov_len);
            if (base) { *out_len = len; return base; }
        }
    }

    return NULL;
}

static __always_inline void
emit_dns(struct sock *sk, struct msghdr *msg, __u64 size, __u8 proto) {
    __u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
    if (family != AF_INET && family != AF_INET6) return;

    __u16 dport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
    if (dport != DNS_PORT) return;

    __u64 buf_len = 0;
    const void *base = first_iov(msg, &buf_len);
    if (!base) return;

    struct dns_evt *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return;

    e->ts_ns   = bpf_ktime_get_ns();
    __u64 pt   = bpf_get_current_pid_tgid();
    e->pid     = pt >> 32;
    e->msg_len = (__u32)size;
    e->dport   = dport;
    e->family  = (__u8)family;
    e->proto   = proto;
    bpf_get_current_comm(e->comm, sizeof(e->comm));

    __u32 to_read = (__u32)buf_len;
    if (to_read > DNS_SNAP_LEN) to_read = DNS_SNAP_LEN;
    e->payload_len = to_read;

    __builtin_memset(e->payload, 0, sizeof(e->payload));
    if (bpf_probe_read_user(e->payload, to_read, base) != 0) {
        e->payload_len = 0;
    }

    bpf_ringbuf_submit(e, 0);
}

/* ---- outbound UDP (the common DNS path) --------------------------- */
SEC("fentry/udp_sendmsg")
int BPF_PROG(on_udp_sendmsg, struct sock *sk, struct msghdr *msg, __u64 size) {
    if (size == 0) return 0;
    emit_dns(sk, msg, size, 0);
    return 0;
}

/* ---- outbound TCP DNS (large responses / zone transfers) ---------- */
SEC("fentry/tcp_sendmsg")
int BPF_PROG(on_tcp_sendmsg, struct sock *sk, struct msghdr *msg, __u64 size) {
    if (size == 0) return 0;
    emit_dns(sk, msg, size, 1);
    return 0;
}
