#ifndef _IP_CONNTRACK_DYNEXPECT_H
#define _IP_CONNTRACK_DYNEXPECT_H

#include <sys/types.h>

#define SO_DYNEXPECT_MAP 11281
#define SO_DYNEXPECT_EXPECT 11282
#define SO_DYNEXPECT_DESTROY 11283
#define SO_DYNEXPECT_MARK 11284

struct ip_ct_dynexpect_map
{
        u_int32_t mapping_id;
        u_int32_t orig_ip;
        u_int32_t new_ip;
        u_int16_t orig_port;
        u_int16_t n_ports;
        u_int16_t new_port;
        u_int8_t proto;
        u_int8_t _res1;
        u_int32_t n_active;
} __attribute__((packed));

struct ip_ct_dynexpect_expect
{
        u_int32_t mapping_id;
        u_int32_t peer_ip;
        u_int16_t peer_port;
} __attribute__((packed));

struct ip_ct_dynexpect_destroy
{
        u_int32_t mapping_id;
} __attribute__((packed));

struct ip_ct_dynexpect_mark
{
        u_int32_t mapping_id;
        u_int32_t mark;
} __attribute__((packed));

#endif /* _IP_CONNTRACK_DYNEXPECT_H */
