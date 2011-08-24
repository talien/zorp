#include <zorp/nfdynexpect-kernel.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <errno.h>

#include <glib.h>

static int sock;

#define CLEAR(m) memset(&m, 0, sizeof(m))

/* checks */
static void
test_availability(void)
{
  struct ip_ct_dynexpect_map map = {
    .mapping_id = 0x7fffffff,
  };
  socklen_t len = sizeof(map);

  g_assert(getsockopt(sock, SOL_IP, SO_DYNEXPECT_MAP, &map, &len) == -1);
  g_assert(errno == ENOENT);
}

static void
test_mapping_api(void)
{
  /* create a mapping */
  struct ip_ct_dynexpect_map map = {
    .proto = IPPROTO_TCP,
    .orig_ip = 0x12345678,
    .orig_port = 256,
    .new_ip = 0x12345676,
    .new_port = 255,
    .n_ports = 2,
  };
  socklen_t len = sizeof(map);

  g_assert(setsockopt(sock, SOL_IP, SO_DYNEXPECT_MAP, &map, len) == 0);

  /* query mapping */
  struct ip_ct_dynexpect_map rmap = {
    .mapping_id = map.mapping_id,
  };

  g_assert(getsockopt(sock, SOL_IP, SO_DYNEXPECT_MAP, &rmap, &len) == 0);
  g_assert(len == sizeof(rmap));
  g_assert(map.mapping_id == rmap.mapping_id);
  g_assert(memcmp(&map, &rmap, sizeof(map)) == 0);

  /* set mark */
  struct ip_ct_dynexpect_mark mark = {
    .mapping_id = rmap.mapping_id,
    .mark = 0xdeadbeef,
  };

  g_assert(setsockopt(sock, SOL_IP, SO_DYNEXPECT_MARK, &mark, sizeof(mark)) == 0);

  /* create expectation */
  struct ip_ct_dynexpect_expect expect = {
    .mapping_id = rmap.mapping_id,
    .peer_ip = 0x23456789,
    .peer_port = 50000,
  };

  g_assert(setsockopt(sock, SOL_IP, SO_DYNEXPECT_EXPECT, &expect, sizeof(expect)) == 0);

  /* destroy mapping */
  struct ip_ct_dynexpect_destroy destroy = {
    .mapping_id = map.mapping_id,
  };

  g_assert(setsockopt(sock, SOL_IP, SO_DYNEXPECT_DESTROY, &destroy, sizeof(destroy)) == 0);
}

static void
test_mapping_timeout(void)
{
  /* create a mapping */
  struct ip_ct_dynexpect_map map = {
    .proto = IPPROTO_TCP,
    .orig_ip = 0x12345678,
    .orig_port = 256,
    .new_ip = 0x12345676,
    .new_port = 255,
    .n_ports = 2,
  };
  socklen_t len = sizeof(map);

  g_assert(setsockopt(sock, SOL_IP, SO_DYNEXPECT_MAP, &map, len) == 0);

  /* query mapping */
  struct ip_ct_dynexpect_map rmap = {
    .mapping_id = map.mapping_id,
  };

  g_assert(getsockopt(sock, SOL_IP, SO_DYNEXPECT_MAP, &rmap, &len) == 0);
  g_assert(len == sizeof(rmap));
  g_assert(map.mapping_id == rmap.mapping_id);
  g_assert(memcmp(&map, &rmap, sizeof(map)) == 0);

  /* create expectation */
  struct ip_ct_dynexpect_expect expect = {
    .mapping_id = rmap.mapping_id,
    .peer_ip = 0x23456789,
    .peer_port = 50000,
  };

  g_assert(setsockopt(sock, SOL_IP, SO_DYNEXPECT_EXPECT, &expect, sizeof(expect)) == 0);

  /* check if the expectations were actually created */
  int res = system("grep -q -E 'l3proto = 2 proto=6 src=18.52.86.120 dst=35.69.103.137 sport=256 dport=50000 dynexpect' /proc/net/nf_conntrack_expect");
  g_assert(WIFEXITED(res) && (WEXITSTATUS(res) == 0));

  res = system("grep -q -E 'l3proto = 2 proto=6 src=18.52.86.120 dst=35.69.103.137 sport=257 dport=50001 dynexpect' /proc/net/nf_conntrack_expect");
  g_assert(WIFEXITED(res) && (WEXITSTATUS(res) == 0));

  /* wait for timeout */
  sleep(7);

  /* check that the expectations have been removed */
  res = system("grep -q dynexpect /proc/net/nf_conntrack_expect");
  g_assert(WIFEXITED(res) && (WEXITSTATUS(res) == 1));

  /* destroy mapping */
  struct ip_ct_dynexpect_destroy destroy = {
    .mapping_id = map.mapping_id,
  };

  g_assert(setsockopt(sock, SOL_IP, SO_DYNEXPECT_DESTROY, &destroy, sizeof(destroy)) < 0);
}

static void
test_expected_connection(void)
{
  /* create a mapping */
  struct ip_ct_dynexpect_map map = {
    .proto = IPPROTO_UDP,
    .orig_ip = 0x7f000001,
    .orig_port = 34000,
    .new_ip = 0x7f000002,
    .new_port = 0,
    .n_ports = 2,
  };
  socklen_t len = sizeof(map);

  g_assert(setsockopt(sock, SOL_IP, SO_DYNEXPECT_MAP, &map, len) == 0);

  /* query mapping */
  struct ip_ct_dynexpect_map rmap = {
    .mapping_id = map.mapping_id,
  };

  g_assert(getsockopt(sock, SOL_IP, SO_DYNEXPECT_MAP, &rmap, &len) == 0);
  g_assert(len == sizeof(rmap));
  g_assert(map.mapping_id == rmap.mapping_id);
  g_assert(rmap.n_active == 0);

  /* set mark */
  struct ip_ct_dynexpect_mark mark = {
    .mapping_id = rmap.mapping_id,
    .mark = 0xbeef,
  };

  g_assert(setsockopt(sock, SOL_IP, SO_DYNEXPECT_MARK, &mark, sizeof(mark)) == 0);

  /* create expectation */
  struct ip_ct_dynexpect_expect expect = {
    .mapping_id = rmap.mapping_id,
    .peer_ip = 0x7f000003,
    .peer_port = 50000,
  };

  g_assert(setsockopt(sock, SOL_IP, SO_DYNEXPECT_EXPECT, &expect, sizeof(expect)) == 0);

  /* create connection */
  int sock = socket(PF_INET, SOCK_DGRAM, 0);
  g_assert(sock > 0);

  struct sockaddr_in name = {
    .sin_family = AF_INET,
    .sin_port = htons(34000),
    .sin_addr.s_addr = htonl(0x7f000001)
  };

  g_assert(bind(sock, (struct sockaddr *) &name, sizeof(name)) == 0);

  struct sockaddr_in dest = {
    .sin_family = AF_INET,
    .sin_port = htons(50000),
    .sin_addr.s_addr = htonl(0x7f000003)
  };

  int res = sendto(sock, &len, sizeof(len), 0, (struct sockaddr *) &dest, sizeof(dest));
  if (res < 0) {
    perror("sendto");
    g_assert_not_reached();
  }

  /* poll the mapping: check that it does not time out and that it has exactly
   * one media stream */
  for (int i = 0; i < 8; i++) {
    /* query mapping */
    struct ip_ct_dynexpect_map rmap = {
      .mapping_id = map.mapping_id
    };

    sleep(1);

    g_assert(getsockopt(sock, SOL_IP, SO_DYNEXPECT_MAP, &rmap, &len) == 0);
    g_assert(len == sizeof(rmap));
    g_assert(rmap.n_active == 1);
  }

  /* check mark value */
  res = system("grep -q -E 'src=127.0.0.1 dst=127.0.0.3 sport=34000 dport=50000 packets=1.*src=127.0.0.3 dst=127.0.0.2 sport=50000.*mark=48879' /proc/net/nf_conntrack");
  g_assert(WIFEXITED(res) && (WEXITSTATUS(res) == 0));

  /* wait for timeout */
  sleep(6);

  /* check that the connection tracking entry was removed on timeout */
  res = system("grep -q -E 'src=127.0.0.1 dst=127.0.0.3 sport=34000 dport=50000 packets=1.*src=127.0.0.3 dst=127.0.0.2 sport=50000' /proc/net/nf_conntrack");
  g_assert(WIFEXITED(res) && (WEXITSTATUS(res) == 1));

  /* check that the expectations have been removed */
  res = system("grep -q dynexpect /proc/net/nf_conntrack_expect");
  g_assert(WIFEXITED(res) && (WEXITSTATUS(res) == 1));

  /* destroy mapping: should fail because the mapping already timed out */
  struct ip_ct_dynexpect_destroy destroy = {
    .mapping_id = rmap.mapping_id,
  };

  g_assert(setsockopt(sock, SOL_IP, SO_DYNEXPECT_DESTROY, &destroy, sizeof(destroy)) < 0);
}

int
main(int argc, char *argv[])
{
  g_test_init(&argc, &argv, NULL);

  sock = socket(AF_INET, SOCK_DGRAM, 0);
  g_assert_cmpint(sock, >, 0);

  /* set mapping timeout to 5 seconds for the duration of the test */
  int res = system("echo 5 > /sys/module/nf_conntrack_dynexpect/parameters/mapping_timeout");
  g_assert(WIFEXITED(res) && (WEXITSTATUS(res) == 0));

  g_test_add_func("/dynexpect/availability", test_availability);
  g_test_add_func("/dynexpect/mapping_api", test_mapping_api);
  g_test_add_func("/dynexpect/timeout", test_mapping_timeout);
  g_test_add_func("/dynexpect/expected_connection", test_expected_connection);

  g_test_run();

  /* reset mapping timeout to the default */
  res = system("echo 300 > /sys/module/nf_conntrack_dynexpect/parameters/mapping_timeout");
  g_assert(WIFEXITED(res) && (WEXITSTATUS(res) == 0));

  return 0;
}
