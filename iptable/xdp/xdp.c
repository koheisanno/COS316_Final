#include <linux/bpf.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <arpa/inet.h>

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 256);
} ip_list SEC(".maps");

SEC("xdp")
int xdp_iptable(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;
    __u16 h_proto;
    struct iphdr *iph;

    // Check if packet is large enough to contain an Ethernet header
    if (data + sizeof(struct ethhdr) > data_end)
        return XDP_DROP;

    // get the protocol from the Ethernet header
    h_proto = eth->h_proto;

    if (h_proto == htons(ETH_P_IP)) {
		iph = data + sizeof(struct ethhdr);

        __u32 ip_src = iph->saddr;
        bpf_printk("source ip address is %u\n", ip_src);
        __u64 *rule_idx = bpf_map_lookup_elem(&ip_list, &ip_src);
        if (rule_idx) {
            // Matched, increase match counter for matched "rule"
            return XDP_DROP;
        }
	}
    
    return XDP_PASS;
}
