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
struct __create_map_def {
  const char *name;
  void *map_data;  // Mock version only: holds head to single linked list of map
                   // items
  struct bpf_map_def *map_def;
  SLIST_ENTRY(__create_map_def) next;
};

// Declaration only. Definition held in mock_map package.
SLIST_HEAD(__maps_head_def, __create_map_def);
extern struct __maps_head_def *__maps_head;

#define BPF_MAP_DEF(x) static struct bpf_map_def x

#define BPF_MAP_ADD(x)                                          \
  static __attribute__((constructor)) void __bpf_map_##x() {    \
    static struct __create_map_def __bpf_map_entry_##x;         \
    __bpf_map_entry_##x.name = #x;                              \
    __bpf_map_entry_##x.map_data = NULL;                        \
    __bpf_map_entry_##x.map_def = &x;                           \
    SLIST_INSERT_HEAD(__maps_head, &__bpf_map_entry_##x, next); \
  }

BPF_MAP_DEF(ip_list) = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u32),
    .max_entries = 256,
};
BPF_MAP_ADD(ip_list);

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
