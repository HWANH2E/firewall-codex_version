#include "firewall.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static bool parse_cidr(const char *token, cidr_match_t *cidr) {
    if (strcmp(token, "any") == 0) {
        cidr->any = true;
        cidr->prefix_len = 0;
        cidr->network.s_addr = 0;
        return true;
    }

    char *slash = strchr(token, '/');
    char addr_buf[32];
    if (!slash) {
        return false;
    }

    size_t len = (size_t)(slash - token);
    if (len >= sizeof(addr_buf)) {
        return false;
    }
    memcpy(addr_buf, token, len);
    addr_buf[len] = '\0';

    int prefix = atoi(slash + 1);
    if (prefix < 0 || prefix > 32) {
        return false;
    }

    if (inet_aton(addr_buf, &cidr->network) == 0) {
        return false;
    }
    cidr->prefix_len = (uint8_t)prefix;
    cidr->any = false;
    return true;
}

static bool parse_port(const char *token, port_match_t *port) {
    if (strcmp(token, "any") == 0) {
        port->any = true;
        port->port = 0;
        return true;
    }

    char *end = NULL;
    long value = strtol(token, &end, 10);
    if (end == token || *end != '\0' || value < 0 || value > 65535) {
        return false;
    }

    port->any = false;
    port->port = (uint16_t)value;
    return true;
}

static rule_proto_t parse_proto(const char *token) {
    if (strcmp(token, "tcp") == 0) {
        return PROTO_TCP;
    }
    if (strcmp(token, "udp") == 0) {
        return PROTO_UDP;
    }
    if (strcmp(token, "icmp") == 0) {
        return PROTO_ICMP;
    }
    if (strcmp(token, "any") == 0) {
        return PROTO_ANY;
    }
    return -1;
}

static rule_action_t parse_action(const char *token) {
    if (strcmp(token, "allow") == 0) {
        return ACTION_ALLOW;
    }
    if (strcmp(token, "deny") == 0) {
        return ACTION_DENY;
    }
    return -1;
}

static bool parse_rule_line(const char *line, firewall_rule_t *rule) {
    char buffer[256];
    strncpy(buffer, line, sizeof(buffer) - 1);
    buffer[sizeof(buffer) - 1] = '\0';

    char *tokens[RULE_TOKEN_MAX] = {0};
    size_t token_count = 0;
    char *saveptr = NULL;
    char *tok = strtok_r(buffer, " \t\n\r", &saveptr);
    while (tok && token_count < RULE_TOKEN_MAX) {
        tokens[token_count++] = tok;
        tok = strtok_r(NULL, " \t\n\r", &saveptr);
    }

    if (token_count < 6) {
        return false;
    }

    rule->action = parse_action(tokens[0]);
    rule->proto = parse_proto(tokens[1]);
    if (rule->action == (rule_action_t)-1 || rule->proto == (rule_proto_t)-1) {
        return false;
    }

    if (!parse_cidr(tokens[2], &rule->src)) {
        return false;
    }
    if (!parse_port(tokens[3], &rule->sport)) {
        return false;
    }
    if (!parse_cidr(tokens[4], &rule->dst)) {
        return false;
    }
    if (!parse_port(tokens[5], &rule->dport)) {
        return false;
    }

    rule->stateful = false;
    if (token_count >= 7 && strcmp(tokens[6], "stateful") == 0) {
        rule->stateful = true;
    }
    return true;
}

bool load_rule_file(const char *path, rule_table_t *table) {
    FILE *fp = fopen(path, "r");
    if (!fp) {
        fprintf(stderr, "Failed to open rule file %s: %s\n", path, strerror(errno));
        return false;
    }

    table->count = 0;
    char line[256];
    while (fgets(line, sizeof(line), fp)) {
        if (line[0] == '#' || line[0] == '\n') {
            continue;
        }
        if (table->count >= MAX_RULES) {
            fprintf(stderr, "Rule table is full, ignoring additional rules\n");
            break;
        }
        firewall_rule_t *rule = &table->rules[table->count];
        if (parse_rule_line(line, rule)) {
            table->count++;
        } else {
            fprintf(stderr, "Skipping invalid rule: %s", line);
        }
    }

    fclose(fp);
    return table->count > 0;
}

static bool match_cidr(const cidr_match_t *cidr, struct in_addr addr) {
    if (cidr->any) {
        return true;
    }
    uint32_t mask = cidr->prefix_len == 0
                        ? 0
                        : htonl(0xFFFFFFFF << (32 - cidr->prefix_len));
    return (addr.s_addr & mask) == (cidr->network.s_addr & mask);
}

static bool match_port(const port_match_t *port_rule, uint16_t port) {
    return port_rule->any || port_rule->port == port;
}

rule_action_t evaluate_rules(const rule_table_t *table, rule_proto_t proto,
                             struct in_addr src_ip, struct in_addr dst_ip,
                             uint16_t src_port, uint16_t dst_port,
                             bool *requires_stateful) {
    *requires_stateful = false;
    for (size_t i = 0; i < table->count; i++) {
        const firewall_rule_t *rule = &table->rules[i];
        if (rule->proto != PROTO_ANY && rule->proto != proto) {
            continue;
        }
        if (!match_cidr(&rule->src, src_ip) || !match_cidr(&rule->dst, dst_ip)) {
            continue;
        }
        if (!match_port(&rule->sport, src_port) || !match_port(&rule->dport, dst_port)) {
            continue;
        }

        *requires_stateful = rule->stateful && proto == PROTO_TCP;
        return rule->action;
    }

    return ACTION_DENY;
}
