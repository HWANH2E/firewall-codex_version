#ifndef FIREWALL_H
#define FIREWALL_H

#include <arpa/inet.h>
#include <netinet/in.h>
#include <pcap/pcap.h>
#include <stdbool.h>
#include <stdint.h>
#include <time.h>

#define MAX_RULES 128
#define MAX_SESSIONS 1024
#define SESSION_TIMEOUT_SEC 300
#define RULE_TOKEN_MAX 8

#define ETHER_TYPE_IPV4 0x0800

/* Firewall rule and policy definitions */
typedef enum {
    ACTION_ALLOW,
    ACTION_DENY
} rule_action_t;

typedef enum {
    PROTO_ANY = 0,
    PROTO_TCP = IPPROTO_TCP,
    PROTO_UDP = IPPROTO_UDP,
    PROTO_ICMP = IPPROTO_ICMP
} rule_proto_t;

typedef struct {
    struct in_addr network;
    uint8_t prefix_len;
    bool any;
} cidr_match_t;

typedef struct {
    uint16_t port;
    bool any;
} port_match_t;

typedef struct {
    rule_action_t action;
    rule_proto_t proto;
    cidr_match_t src;
    cidr_match_t dst;
    port_match_t sport;
    port_match_t dport;
    bool stateful;
} firewall_rule_t;

typedef struct {
    firewall_rule_t rules[MAX_RULES];
    size_t count;
} rule_table_t;

/* TCP session tracking */
typedef enum {
    TCP_NONE = 0,
    TCP_SYN_SENT,
    TCP_SYN_RECV,
    TCP_ESTABLISHED,
    TCP_FIN_WAIT,
    TCP_CLOSED
} tcp_state_t;

typedef struct {
    struct in_addr src_ip;
    struct in_addr dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    tcp_state_t state;
    time_t last_seen;
} session_entry_t;

typedef struct {
    session_entry_t entries[MAX_SESSIONS];
    size_t count;
} session_table_t;

/* Packet parsing helpers */
typedef struct __attribute__((packed)) {
    uint8_t dst[6];
    uint8_t src[6];
    uint16_t ethertype;
} ethernet_header_t;

typedef struct __attribute__((packed)) {
    uint8_t ver_ihl;
    uint8_t tos;
    uint16_t tot_len;
    uint16_t id;
    uint16_t frag_off;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t check;
    uint32_t saddr;
    uint32_t daddr;
} ipv4_header_t;

typedef struct __attribute__((packed)) {
    uint16_t source;
    uint16_t dest;
    uint32_t seq;
    uint32_t ack_seq;
    uint8_t offset_reserved;
    uint8_t flags;
    uint16_t window;
    uint16_t check;
    uint16_t urg_ptr;
} tcp_header_t;

typedef struct __attribute__((packed)) {
    uint16_t source;
    uint16_t dest;
    uint16_t len;
    uint16_t check;
} udp_header_t;

/* Rule and session management */
bool load_rule_file(const char *path, rule_table_t *table);
rule_action_t evaluate_rules(const rule_table_t *table, rule_proto_t proto,
                             struct in_addr src_ip, struct in_addr dst_ip,
                             uint16_t src_port, uint16_t dst_port,
                             bool *requires_stateful);

session_entry_t *lookup_session(session_table_t *table, struct in_addr src,
                                struct in_addr dst, uint16_t sport, uint16_t dport);
void update_session_table(session_table_t *table, struct in_addr src,
                          struct in_addr dst, uint16_t sport, uint16_t dport,
                          const tcp_header_t *tcp);
void expire_sessions(session_table_t *table);

/* Packet handling */
void packet_handler(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes);

#endif // FIREWALL_H
