#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <arpa/inet.h>

SEC("xdp")
int xdp_iptable(struct xdp_md *ctx)
{
    return XDP_TX;
}
