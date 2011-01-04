

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>

#include "inX_addr.h"

static unsigned char v4_in_v6_prefix[12] = {0,0,0,0,0,0,0,0,0,0,0xFF,0xFF};

#if USE_IPV6
static int
is_v4_in_v6(const struct in6_addr *addr)
{
    return (0 == memcmp(addr, v4_in_v6_prefix, 12));
}
#endif


const char *
inXaddr_ntop(const inX_addr *a, char *buf, socklen_t len)
{
	const char *p;
#if USE_IPV6
	if (!is_v4_in_v6(&a->in6))
		p = inet_ntop(AF_INET6, &a->in6, buf, len);
	else
#endif
	p =  inet_ntop(AF_INET, &a->_.in4, buf, len);
	if (p)
		return p;
	return "[unprintable]";
}

int
inXaddr_pton(const char *buf, inX_addr *a)
{
#if USE_IPV6
	if (strchr(buf, ':'))
		return inet_pton(AF_INET6, buf, a);
	memcpy(a, v4_in_v6_prefix, 12);
#endif
	return inet_pton(AF_INET, buf, &a->_.in4);
}

unsigned int
inXaddr_hash(const inX_addr *a, unsigned int bits)
{
        static const uint32_t A = 2654435769U;  // closest prime to 2^32 * $goldenratio
        /*
         * Fibonacci hashing 
         * see http://www.brpreiss.com/books/opus4/html/page214.html
         * Note ignores upper parts of IPv6
         */
        return (A * ntohl(a->_.in4.s_addr)) >> (32 - bits);
}

int
inXaddr_cmp(const inX_addr *a, const inX_addr *b)
{
        if (ntohl(a->_.in4.s_addr) < ntohl(b->_.in4.s_addr))
                return -1;
        if (ntohl(a->_.in4.s_addr) > ntohl(b->_.in4.s_addr))
                return 1;
#if USE_IPV6
	if (is_v4_in_v6(&a->in6))
		return 0;
        if (ntohl(a->_.pad2.s_addr) < ntohl(b->_.pad2.s_addr))
                return -1;
        if (ntohl(a->_.pad2.s_addr) > ntohl(b->_.pad2.s_addr))
                return 1;
        if (ntohl(a->_.pad1.s_addr) < ntohl(b->_.pad1.s_addr))
                return -1;
        if (ntohl(a->_.pad1.s_addr) > ntohl(b->_.pad1.s_addr))
                return 1;
        if (ntohl(a->_.pad0.s_addr) < ntohl(b->_.pad0.s_addr))
                return -1;
        if (ntohl(a->_.pad0.s_addr) > ntohl(b->_.pad0.s_addr))
                return 1;
#endif
	return 0;
}

inX_addr
inXaddr_mask (const inX_addr *a, const inX_addr *mask)
{
	inX_addr masked;
	masked._.in4.s_addr = a->_.in4.s_addr & mask->_.in4.s_addr;
#if USE_IPV6
	if (is_v4_in_v6(&a->in6)) {
		masked._.pad2.s_addr = a->_.pad2.s_addr;
		masked._.pad1.s_addr = a->_.pad1.s_addr;
		masked._.pad0.s_addr = a->_.pad0.s_addr;
	} else {
		masked._.pad2.s_addr = a->_.pad2.s_addr & mask->_.pad2.s_addr;
		masked._.pad1.s_addr = a->_.pad1.s_addr & mask->_.pad1.s_addr;
		masked._.pad0.s_addr = a->_.pad0.s_addr & mask->_.pad0.s_addr;
	}
#endif
	return masked;
}

int
inXaddr_version(const inX_addr *a)
{
#if USE_IPV6
	if (!is_v4_in_v6(&a->in6))
		return 6;
#endif
	return 4;
}

int
inXaddr_assign_v4(inX_addr *dst, const struct in_addr *src)
{
#if USE_IPV6
	memcpy(dst, v4_in_v6_prefix, 12);
#endif
	/* memcpy() instead of struct assignment in case src is not aligned */
	memcpy(&dst->_.in4, src, sizeof(*src));
	return 0;
}

#if USE_IPV6
int
inXaddr_assign_v6(inX_addr *dst, const struct in6_addr *src)
{
	/* memcpy() instead of struct assignment in case src is not aligned */
	memcpy(&dst->in6, src, sizeof(*src));
	return 0;
}
#endif


