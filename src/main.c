#include "firewall.h"

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static rule_table_t rule_table;
static session_table_t session_table;
static pcap_t *pcap_handle = NULL;
static volatile sig_atomic_t stop_capture = 0;

static void print_ip(struct in_addr addr, char *buf, size_t len) {
    inet_ntop(AF_INET, &addr, buf, len);
}

static void print_action(rule_action_t action, const char *reason) {
    const char *label = action == ACTION_ALLOW ? "ALLOW" : "DENY";
    printf("[%s] %s\n", label, reason);
}

static bool tcp_state_allowed(session_entry_t *entry, const tcp_header_t *tcp) {
    uint8_t flags = tcp->flags;
    bool syn = flags & 0x02;
    bool ack = flags & 0x10;

    if (!entry && syn && !ack) {
        return true; // new connection
    }
    if (!entry) {
        return false;
    }

    return entry->state == TCP_SYN_SENT || entry->state == TCP_SYN_RECV ||
           entry->state == TCP_ESTABLISHED || (entry->state == TCP_FIN_WAIT && (flags & 0x01));
}

void packet_handler(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes) {
    (void)user;
    if (h->caplen < sizeof(ethernet_header_t)) {
        return;
    }

    const ethernet_header_t *eth = (const ethernet_header_t *)bytes;
    if (ntohs(eth->ethertype) != ETHER_TYPE_IPV4) {
        return;
    }

    const u_char *ip_start = bytes + sizeof(ethernet_header_t);
    if ((size_t)(bytes + h->caplen - ip_start) < sizeof(ipv4_header_t)) {
        return;
    }

    const ipv4_header_t *ip = (const ipv4_header_t *)ip_start;
    uint8_t ip_header_len = (ip->ver_ihl & 0x0F) * 4;
    if (ip_header_len < sizeof(ipv4_header_t) || ip_header_len > h->caplen - sizeof(ethernet_header_t)) {
        return;
    }

    rule_proto_t proto = (rule_proto_t)ip->protocol;
    struct in_addr src_addr = {.s_addr = ip->saddr};
    struct in_addr dst_addr = {.s_addr = ip->daddr};
    uint16_t src_port = 0;
    uint16_t dst_port = 0;

    const u_char *l4_start = ip_start + ip_header_len;
    size_t l4_len = h->caplen - (l4_start - bytes);

    if (proto == PROTO_TCP && l4_len >= sizeof(tcp_header_t)) {
        const tcp_header_t *tcp = (const tcp_header_t *)l4_start;
        src_port = ntohs(tcp->source);
        dst_port = ntohs(tcp->dest);

        bool requires_stateful = false;
        rule_action_t action = evaluate_rules(&rule_table, proto, src_addr, dst_addr, src_port, dst_port, &requires_stateful);
        session_entry_t *session = lookup_session(&session_table, src_addr, dst_addr, src_port, dst_port);

        if (requires_stateful && !tcp_state_allowed(session, tcp)) {
            print_action(ACTION_DENY, "TCP state validation failed");
            return;
        }

        if (action == ACTION_DENY) {
            char src_ip[INET_ADDRSTRLEN];
            char dst_ip[INET_ADDRSTRLEN];
            print_ip(src_addr, src_ip, sizeof(src_ip));
            print_ip(dst_addr, dst_ip, sizeof(dst_ip));

            char reason[128];
            snprintf(reason, sizeof(reason), "TCP %s:%u -> %s:%u", src_ip, src_port, dst_ip, dst_port);
            print_action(action, reason);
            return;
        }

        update_session_table(&session_table, src_addr, dst_addr, src_port, dst_port, tcp);
        expire_sessions(&session_table);

        char src_ip[INET_ADDRSTRLEN];
        char dst_ip[INET_ADDRSTRLEN];
        print_ip(src_addr, src_ip, sizeof(src_ip));
        print_ip(dst_addr, dst_ip, sizeof(dst_ip));

        char reason[128];
        snprintf(reason, sizeof(reason), "TCP %s:%u -> %s:%u", src_ip, src_port, dst_ip, dst_port);
        print_action(action, reason);
        return;
    } else if (proto == PROTO_UDP && l4_len >= sizeof(udp_header_t)) {
        const udp_header_t *udp = (const udp_header_t *)l4_start;
        src_port = ntohs(udp->source);
        dst_port = ntohs(udp->dest);
    }

    bool requires_stateful = false;
    rule_action_t action = evaluate_rules(&rule_table, proto, src_addr, dst_addr, src_port, dst_port, &requires_stateful);

    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];
    print_ip(src_addr, src_ip, sizeof(src_ip));
    print_ip(dst_addr, dst_ip, sizeof(dst_ip));

    char reason[128];
    snprintf(reason, sizeof(reason), "%s %s -> %s", proto == PROTO_UDP ? "UDP" : (proto == PROTO_ICMP ? "ICMP" : "IP"),
             src_ip, dst_ip);
    print_action(action, reason);
    (void)requires_stateful; // unused for non TCP
}

static void handle_signal(int sig) {
    (void)sig;
    stop_capture = 1;
    if (pcap_handle) {
        pcap_breakloop(pcap_handle);
    }
}

static void usage(const char *prog) {
    fprintf(stderr, "Usage: %s -i <interface> -r <rule_file>\n", prog);
}

int main(int argc, char **argv) {
    const char *interface = NULL;
    const char *rule_file = "rules.conf";

    int opt;
    while ((opt = getopt(argc, argv, "i:r:")) != -1) {
        switch (opt) {
        case 'i':
            interface = optarg;
            break;
        case 'r':
            rule_file = optarg;
            break;
        default:
            usage(argv[0]);
            return EXIT_FAILURE;
        }
    }

    if (!interface) {
        usage(argv[0]);
        return EXIT_FAILURE;
    }

    if (!load_rule_file(rule_file, &rule_table)) {
        fprintf(stderr, "Failed to load firewall rules\n");
        return EXIT_FAILURE;
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);
    if (!pcap_handle) {
        fprintf(stderr, "Failed to open interface %s: %s\n", interface, errbuf);
        return EXIT_FAILURE;
    }

    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    printf("Starting firewall on %s with %zu rules...\n", interface, rule_table.count);
    if (pcap_loop(pcap_handle, -1, packet_handler, NULL) == -1 && !stop_capture) {
        fprintf(stderr, "pcap_loop error: %s\n", pcap_geterr(pcap_handle));
    }

    pcap_close(pcap_handle);
    printf("Firewall stopped.\n");
    return EXIT_SUCCESS;
}
