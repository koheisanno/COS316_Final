#include <linux/bpf.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <arpa/inet.h>
#include <sys/queue.h>

struct bpf_map_def {
	unsigned int map_type;
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

BPF_MAP_DEF(blacklist) = {
    .map_type = BPF_MAP_TYPE_LPM_TRIE,
    .key_size = sizeof(__u64),
    .value_size = sizeof(__u32),
    .max_entries = 16,
};
BPF_MAP_ADD(blacklist);

// XDP program //
SEC("xdp")
int firewall(struct xdp_md *ctx) {
  void *data_end = (void *)(long)ctx->data_end;
  void *data = (void *)(long)ctx->data;

  // Only IPv4 supported for this example
  struct ethhdr *ether = data;
  if (data + sizeof(*ether) > data_end) {
    // Malformed Ethernet header
    return XDP_ABORTED;
  }

  if (ether->h_proto != 0x08U) {  // htons(ETH_P_IP) -> 0x08U
    // Non IPv4 traffic
    return XDP_PASS;
  }

  data += sizeof(*ether);
  struct iphdr *ip = data;
  if (data + sizeof(*ip) > data_end) {
    // Malformed IPv4 header
    return XDP_ABORTED;
  }

  struct {
    __u32 prefixlen;
    __u32 saddr;
  } key;

  key.prefixlen = 32;
  key.saddr = ip->saddr;

  // Lookup SRC IP in blacklisted IPs
  __u64 *rule_idx = bpf_map_lookup_elem(&blacklist, &key);
  if (rule_idx) {
    // Matched, increase match counter for matched "rule"
    __u32 index = *(__u32*)rule_idx;  // make verifier happy
    return XDP_DROP;
  }

  return XDP_PASS;
}