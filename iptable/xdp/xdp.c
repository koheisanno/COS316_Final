#include <linux/bpf.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <arpa/inet.h>

struct bpf_map_def {
	unsigned int type;
	unsigned int key_size;
	unsigned int value_size;
	unsigned int max_entries;
};

struct bpf_map_def SEC("maps") ip_list = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u32),
    .max_entries = 256,
};

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
