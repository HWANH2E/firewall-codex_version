#include "firewall.h"

#include <stdio.h>
#include <string.h>

static bool tcp_flag_set(const tcp_header_t *tcp, uint8_t flag) {
    return (tcp->flags & flag) != 0;
}

session_entry_t *lookup_session(session_table_t *table, struct in_addr src,
                                struct in_addr dst, uint16_t sport, uint16_t dport) {
    for (size_t i = 0; i < table->count; i++) {
        session_entry_t *entry = &table->entries[i];
        bool forward = entry->src_ip.s_addr == src.s_addr && entry->dst_ip.s_addr == dst.s_addr &&
                        entry->src_port == sport && entry->dst_port == dport;
        bool reverse = entry->src_ip.s_addr == dst.s_addr && entry->dst_ip.s_addr == src.s_addr &&
                        entry->src_port == dport && entry->dst_port == sport;
        if (forward || reverse) {
            entry->last_seen = time(NULL);
            return entry;
        }
    }
    return NULL;
}

static void insert_session(session_table_t *table, struct in_addr src, struct in_addr dst,
                           uint16_t sport, uint16_t dport, tcp_state_t state) {
    if (table->count >= MAX_SESSIONS) {
        fprintf(stderr, "Session table full, dropping new session\n");
        return;
    }
    session_entry_t *entry = &table->entries[table->count++];
    entry->src_ip = src;
    entry->dst_ip = dst;
    entry->src_port = sport;
    entry->dst_port = dport;
    entry->state = state;
    entry->last_seen = time(NULL);
}

static tcp_state_t advance_state(tcp_state_t current, const tcp_header_t *tcp, bool from_initiator) {
    bool syn = tcp_flag_set(tcp, 0x02);
    bool ack = tcp_flag_set(tcp, 0x10);
    bool fin = tcp_flag_set(tcp, 0x01);
    bool rst = tcp_flag_set(tcp, 0x04);

    if (rst) {
        return TCP_CLOSED;
    }

    switch (current) {
    case TCP_NONE:
        if (syn && !ack) {
            return TCP_SYN_SENT;
        }
        break;
    case TCP_SYN_SENT:
        if (syn && ack && !from_initiator) {
            return TCP_SYN_RECV;
        }
        break;
    case TCP_SYN_RECV:
        if (ack) {
            return TCP_ESTABLISHED;
        }
        break;
    case TCP_ESTABLISHED:
        if (fin) {
            return TCP_FIN_WAIT;
        }
        break;
    case TCP_FIN_WAIT:
        if (fin && ack) {
            return TCP_CLOSED;
        }
        break;
    default:
        break;
    }

    return current;
}

void update_session_table(session_table_t *table, struct in_addr src,
                          struct in_addr dst, uint16_t sport, uint16_t dport,
                          const tcp_header_t *tcp) {
    session_entry_t *entry = lookup_session(table, src, dst, sport, dport);
    bool from_initiator = true;
    if (!entry) {
        insert_session(table, src, dst, sport, dport, TCP_NONE);
        entry = &table->entries[table->count - 1];
    } else {
        from_initiator = entry->src_ip.s_addr == src.s_addr && entry->src_port == sport;
    }

    entry->state = advance_state(entry->state, tcp, from_initiator);
    entry->last_seen = time(NULL);
}

void expire_sessions(session_table_t *table) {
    time_t now = time(NULL);
    size_t write_idx = 0;
    for (size_t read_idx = 0; read_idx < table->count; read_idx++) {
        session_entry_t *entry = &table->entries[read_idx];
        if (difftime(now, entry->last_seen) > SESSION_TIMEOUT_SEC || entry->state == TCP_CLOSED) {
            continue;
        }
        if (write_idx != read_idx) {
            table->entries[write_idx] = *entry;
        }
        write_idx++;
    }
    table->count = write_idx;
}
