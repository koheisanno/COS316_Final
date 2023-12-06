#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_iptable(struct xdp_md *ctx)
{
    return XDP_DROP;
}
