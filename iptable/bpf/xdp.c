#include "bpf_helpers.h"
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/ip.h>


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

  if (ether->h_proto != htons(ETH_P_IP)) {
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
    __u32 index = *(__u32*)rule_idx;
    return XDP_DROP;
  }

  return XDP_PASS;
}