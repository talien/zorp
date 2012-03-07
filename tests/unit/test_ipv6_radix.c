#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

#include <glib.h>

/************************************************************************/
/************************************************************************/
/************************************************************************/

/* These are routinges copied from the Linux kernel to be able to
 * compile the radix tree code in user-space. Obviously these are
 * under GPL.
 */
#ifndef __KERNEL__

typedef guint32 __be32;
typedef guint16 __u16;

/**
 * fls - find last set bit in word
 * @x: the word to search
 *
 * This is defined in a similar way as the libc and compiler builtin
 * ffs, but returns the position of the most significant set bit.
 *
 * fls(value) returns 0 if value is 0 or the position of the last
 * set bit if value is nonzero. The last (most significant) bit is
 * at position 32.
 */
static inline int fls(int x)
{
	int r;

	asm("bsrl %1,%0\n\t"
	    "cmovzl %2,%0"
	    : "=&r" (r) : "rm" (x), "rm" (-1));

	return r + 1;
}


static inline void ipv6_addr_copy(struct in6_addr *a1, const struct in6_addr *a2)
{
	memcpy(a1, a2, sizeof(struct in6_addr));
}

static inline int __ipv6_prefix_equal(const __be32 *a1, const __be32 *a2,
				      unsigned int prefixlen)
{
	unsigned pdw, pbi;

	/* check complete u32 in prefix */
	pdw = prefixlen >> 5;
	if (pdw && memcmp(a1, a2, pdw << 2))
		return 0;

	/* check incomplete u32 in prefix */
	pbi = prefixlen & 0x1f;
	if (pbi && ((a1[pdw] ^ a2[pdw]) & htonl((0xffffffff) << (32 - pbi))))
		return 0;

	return 1;
}

static inline int ipv6_prefix_equal(const struct in6_addr *a1,
				    const struct in6_addr *a2,
				    unsigned int prefixlen)
{
	return __ipv6_prefix_equal(a1->s6_addr32, a2->s6_addr32,
				   prefixlen);
}

/*
 * find the first different bit between two addresses
 * length of address must be a multiple of 32bits
 */
static inline int __ipv6_addr_diff(const void *token1, const void *token2, int addrlen)
{
	const __be32 *a1 = token1, *a2 = token2;
	int i;

	addrlen >>= 2;

	for (i = 0; i < addrlen; i++) {
		__be32 xb = a1[i] ^ a2[i];
		if (xb)
			return i * 32 + 32 - fls(ntohl(xb));
	}

	/*
	 *	we should *never* get to this point since that 
	 *	would mean the addrs are equal
	 *
	 *	However, we do get to it 8) And exacly, when
	 *	addresses are equal 8)
	 *
	 *	ip route add 1111::/128 via ...
	 *	ip route add 1111::/64 via ...
	 *	and we are here.
	 *
	 *	Ideally, this function should stop comparison
	 *	at prefix length. It does not, but it is still OK,
	 *	if returned value is greater than prefix length.
	 *					--ANK (980803)
	 */
	return (addrlen << 5);
}

static inline int ipv6_addr_diff(const struct in6_addr *a1, const struct in6_addr *a2)
{
	return __ipv6_addr_diff(a1, a2, sizeof(struct in6_addr));
}

/* Fake kzorp structures/code */
struct kz_zone {};
static inline void kz_zone_put(struct kz_zone *z G_GNUC_UNUSED) {};

#endif


/************************************************************************/
/************************************************************************/
/************************************************************************/

#include "kzorp_radix.c"

/************************************************************************/
/************************************************************************/
/************************************************************************/

static struct in6_addr *
string_as_address_v6(const char *src)
{
	static struct in6_addr _buf;

	g_assert(inet_pton(AF_INET6, src, &_buf));

	return &_buf;
}

static struct in_addr *
string_as_address_v4(const char *src)
{
	static struct in_addr _buf;

	g_assert(inet_pton(AF_INET, src, &_buf));

	return &_buf;
}

static const char *
address_as_string(const struct in6_addr *addr)
{
	static char _buf[256];

	g_assert(inet_ntop(AF_INET6, addr, _buf, sizeof(_buf)));

	return _buf;
}

static void
__print_node(GString *str, int level, const struct kz_lookup_ipv6_node *node)
{
	if (node->zone)
		g_string_append_printf(str, "%*d|%s/%d -> '%s'\n", 2 * level, level, address_as_string(&node->addr), node->prefix_len, (char *)node->zone);
	else
		g_string_append_printf(str, "%*d|%s/%d\n", 2 * level, level, address_as_string(&node->addr), node->prefix_len);
}

static void
__print_tree(GString *str, int level, const struct kz_lookup_ipv6_node *node)
{
	if (node == NULL)
		return;
	__print_node(str, level, node);
	__print_tree(str, level + 1, node->left);
	__print_tree(str, level + 1, node->right);
}

static const char *
tree_as_string(const struct kz_lookup_ipv6_node *root){

	static GString *_str = NULL;

	if (_str == NULL) {
		_str = g_string_new("");
	}

	g_string_assign(_str, "");
	__print_tree(_str, 0, root);

	return _str->str;
}

#define TREE_NEW(root) do { if (root) ipv6_destroy(root); root = ipv6_node_new(); } while (0);
#define TREE_ADD(root, net, prefix) ipv6_add(root, string_as_address_v6(net), prefix)
#define TREE_ADD_DATA(root, net, prefix, data)				\
	do {								\
		struct kz_lookup_ipv6_node *n = ipv6_add(root, string_as_address_v6(net), prefix); \
		if (n)							\
			n->zone= (struct kz_zone *) data;		\
	} while (0);
#define TREE_PRINT(root) printf("%s", tree_as_string(root))
#define TREE_CHECK(root, str) do { if (g_test_verbose()) TREE_PRINT(root);\
		g_assert_cmpstr(tree_as_string(root), ==, str); } while (0);
#define TREE_LOOKUP(root, address, expected)				\
	do {								\
		struct kz_lookup_ipv6_node *n = ipv6_lookup(root, string_as_address_v6(address)); \
		g_assert(n != NULL);					\
		g_assert_cmpstr((char *)n->zone, ==, expected);		\
	} while (0);
#define TREE_LOOKUP_FAILS(root, address)				\
	do {								\
		struct kz_lookup_ipv6_node *n = ipv6_lookup(root, string_as_address_v6(address)); \
		g_assert(n == NULL || n->zone == NULL);			\
	} while (0);
	
static void
test_print(void)
{
	struct kz_lookup_ipv6_node *root = ipv6_node_new();

	TREE_CHECK(root,
		   "0|::/0\n");

	TREE_ADD(root, "::", 32);
	TREE_ADD(root, "::", 64);
	TREE_ADD(root, "ffff::", 16);
	TREE_ADD(root, "ffff:ff00::", 32);
	TREE_ADD(root, "ffff:f000::", 32);
	TREE_CHECK(root,
		   "0|::/0\n"
		   " 1|::/32\n"
		   "   2|::/64\n"
		   " 1|ffff::/16\n"
		   "   2|ffff:f000::/20\n"
		   "     3|ffff:f000::/32\n"
		   "     3|ffff:ff00::/32\n");

	ipv6_destroy(root);
}

static void
test_add(void)
{
	struct kz_lookup_ipv6_node *root = NULL;

	/* construct an empty tree */
	TREE_NEW(root);
	TREE_CHECK(root,
		   "0|::/0\n");

	/* postfix insertion */
	TREE_ADD(root, "ffff::", 15);
	TREE_ADD(root, "ffff:ffff::", 31);
	TREE_CHECK(root, 
		   "0|::/0\n"
		   " 1|ffff::/15\n"
		   "   2|ffff:ffff::/31\n");

	TREE_NEW(root);
	TREE_ADD(root, "::", 15);
	TREE_ADD(root, "::", 31);
	TREE_CHECK(root, 
		   "0|::/0\n"
		   " 1|::/15\n"
		   "   2|::/31\n");

	/* inserting shorter prefix */
	TREE_NEW(root);
	TREE_ADD(root, "ffff:ffff::", 31);
	TREE_ADD(root, "ffff::", 15);
	TREE_CHECK(root, 
		   "0|::/0\n"
		   " 1|ffff::/15\n"
		   "   2|ffff:ffff::/31\n");

	TREE_NEW(root);
	TREE_ADD(root, "::", 31);
	TREE_ADD(root, "::", 15);
	TREE_CHECK(root, 
		   "0|::/0\n"
		   " 1|::/15\n"
		   "   2|::/31\n");

	/* same prefix length, but different prefix */
	TREE_NEW(root);
	TREE_ADD(root, "ffff::", 16);
	TREE_ADD(root, "f0ff::", 16);
	TREE_CHECK(root,
		   "0|::/0\n"
		   " 1|f0ff::/4\n"
		   "   2|f0ff::/16\n"
		   "   2|ffff::/16\n");

	TREE_NEW(root);
	TREE_ADD(root, "00ff::", 16);
	TREE_ADD(root, "0fff::", 16);
	TREE_CHECK(root,
		   "0|::/0\n"
		   " 1|fff::/4\n"
		   "   2|ff::/16\n"
		   "   2|fff::/16\n");

	/* adding a node already present */
	TREE_NEW(root);
	TREE_ADD(root, "fe80::", 10);
	TREE_ADD(root, "fe80::", 10);
	TREE_ADD(root, "fe8f::", 10);
	TREE_CHECK(root,
		   "0|::/0\n"
		   " 1|fe80::/10\n");

	ipv6_destroy(root);
}

static void
test_lookup(void)
{
	struct kz_lookup_ipv6_node *root = NULL;

	/* empty tree */
	TREE_NEW(root);
	TREE_LOOKUP_FAILS(root, "::1");

	/* add a single subnet */
	TREE_NEW(root);
	TREE_ADD_DATA(root, "fe80::", 10, "link-local");
	TREE_LOOKUP(root, "fe80:1::", "link-local");
	TREE_LOOKUP_FAILS(root, "::1");
	TREE_LOOKUP_FAILS(root, "fe00::");

	/* check best match */
	TREE_NEW(root);
	TREE_ADD_DATA(root, "::f000", 116, "subnet1");
	TREE_LOOKUP(root, "::ffff", "subnet1");
	TREE_ADD_DATA(root, "::f800", 117, "subnet11");
	TREE_LOOKUP(root, "::ffff", "subnet11");
	TREE_ADD_DATA(root, "::f000", 117, "subnet12");
	TREE_LOOKUP(root, "::ffff", "subnet11");
	TREE_LOOKUP(root, "::f0ff", "subnet12");

	/* exact match */
	TREE_ADD_DATA(root, "::ffff", 128, "exact1");
	TREE_LOOKUP(root, "::ffff", "exact1");
	TREE_ADD_DATA(root, "::fffe", 128, "exact2");
	TREE_LOOKUP(root, "::ffff", "exact1");
	TREE_LOOKUP(root, "::fffe", "exact2");
	TREE_LOOKUP(root, "::fff0", "subnet11");

	ipv6_destroy(root);
}

/************************************************************************/
/************************************************************************/
/************************************************************************/

#include "kzorp_mask.c"

/************************************************************************/
/************************************************************************/
/************************************************************************/

#define TEST_MASK(mask, length) do { g_assert_cmpint(mask_to_size_v4(string_as_address_v4(mask)), ==, length); } while (0);

static void
test_mask_v4(void)
{
	TEST_MASK("0.0.0.0", 0);
	TEST_MASK("128.0.0.0", 1);
	TEST_MASK("255.255.255.0", 24);
	TEST_MASK("255.255.255.128", 25);
	TEST_MASK("255.255.255.255", 32);
}

#undef TEST_MASK

#define TEST_MASK(mask, length) do { g_assert_cmpint(mask_to_size_v6(string_as_address_v6(mask)), ==, length); } while (0);

static void
test_mask_v6(void)
{
	TEST_MASK("::", 0);
	TEST_MASK("8000::", 1);
	TEST_MASK("f000::", 4);
	TEST_MASK("fffe::", 15);
	TEST_MASK("ffff::", 16);
	TEST_MASK("ffff:8000::", 17);
	TEST_MASK("ffff:c000::", 18);
	TEST_MASK("ffff:ffff::", 32);
	TEST_MASK("ffff:ffff:8000::", 33);
	TEST_MASK("ffff:ffff:ffff:ffff:ffff:fffe:0000:0000", 95);
	TEST_MASK("ffff:ffff:ffff:ffff:ffff:ffff:0000:0000", 96);
	TEST_MASK("ffff:ffff:ffff:ffff:ffff:ffff:8000:0000", 97);
	TEST_MASK("ffff:ffff:ffff:ffff:ffff:ffff:ffff:0000", 112);
	TEST_MASK("ffff:ffff:ffff:ffff:ffff:ffff:ffff:8000", 113);
	TEST_MASK("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", 128);
}

#undef TEST_MASK

int
main(int argc, char *argv[])
{
	g_test_init(&argc, &argv, NULL);

	g_test_add_func("/radix/print", test_print);
	g_test_add_func("/radix/add", test_add);
	g_test_add_func("/radix/lookup", test_lookup);

	g_test_add_func("/util/mask_v4", test_mask_v4);
	g_test_add_func("/util/mask_v6", test_mask_v6);

	g_test_run();

	return EXIT_SUCCESS;
}
