#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <arpa/inet.h>

SEC("xdp")
int xdp_iptable(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;
    __u16 h_proto;

    // Check if packet is large enough to contain an Ethernet header
    if (data + sizeof(struct ethhdr) > data_end)
        return XDP_DROP;

    // get the protocol from the Ethernet header
    h_proto = eth->h_proto;

    // drop if the protocol is IPv6
    if (h_proto == htons(ETH_P_IPV6))
        return XDP_PASS;

    return XDP_DROP;
}
