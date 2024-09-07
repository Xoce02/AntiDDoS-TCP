#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/icmp.h>
#include <bpf/bpf_helpers.h>

// Mapa BPF para registrar estadísticas de paquetes
struct bpf_map_def SEC("maps") packet_stats = {
    .type = BPF_MAP_TYPE_PERCPU_ARRAY,
    .key_size = sizeof(u32),
    .value_size = sizeof(u64),
    .max_entries = 256, 
};

SEC("xdp_tcp_network_filter")
int xdp_filter_func(struct xdp_md *ctx) {
    void *data = (void *)(unsigned long)ctx->data;
    void *data_end = (void *)(unsigned long)ctx->data_end;

    if (data + sizeof(struct ethhdr) > data_end) {
        return XDP_PASS;
    }

    struct ethhdr *eth = data;

    if (eth->h_proto != __constant_htons(ETH_P_IP)) {
        return XDP_PASS;
    }

    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end) {
        return XDP_PASS;
    }

    struct iphdr *ip = data + sizeof(struct ethhdr);

    if (ip->protocol == IPPROTO_TCP) {
        if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr) > data_end) {
            return XDP_PASS;
        }

        struct tcphdr *tcp = data + sizeof(struct ethhdr) + sizeof(struct iphdr);

        // Incrementa el contador de paquetes TCP
        u32 key = 0;
        u64 *counter = bpf_map_lookup_elem(&packet_stats, &key);
        if (counter) {
            __sync_fetch_and_add(counter, 1);
        }

        // Filtrado avanzado TCP
        if (tcp->syn && !tcp->ack) {
            return XDP_DROP;  
        } else if (tcp->fin && !tcp->ack) {
            return XDP_DROP;
        } else if (tcp->rst) {
            return XDP_DROP;
        } else if (tcp->syn && tcp->fin) {
            return XDP_DROP;
        } else if (tcp->psh && tcp->urg) {
            return XDP_DROP;
        } else if (!tcp->syn && !tcp->fin && !tcp->rst && !tcp->psh && !tcp->ack && !tcp->urg) {
            return XDP_DROP;
        } else if (tcp->fin && tcp->psh && tcp->urg) {
            return XDP_DROP;
        } else if (tcp->doff < 5 || tcp->doff > 15) {
            return XDP_DROP;
        } else if (tcp->ack && !(tcp->syn || tcp->fin || tcp->rst || tcp->psh || tcp->urg)) {
            return XDP_DROP;
        } else if (tcp->syn && tcp->ack) {
            return XDP_DROP;
        } else if (tcp->window == 0) {
            return XDP_DROP; 
        } else if (ip->saddr == ip->daddr) {
            return XDP_DROP;  
        } else if (ip->frag_off & htons(IP_MF | IP_OFFSET)) {
            return XDP_DROP;  
        }
    } else if (ip->protocol == IPPROTO_ICMP) {
        if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct icmphdr) > data_end) {
            return XDP_PASS;
        }

        struct icmphdr *icmp = data + sizeof(struct ethhdr) + sizeof(struct iphdr);

        if (icmp->type == ICMP_ECHO && icmp->code == 0) {
            return XDP_DROP;
        } else if (icmp->type == ICMP_ECHOREPLY && icmp->code == 0) {
            return XDP_DROP;
        }
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
