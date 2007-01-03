/*
 * $Id$
 * 
 * http://dnstop.measurement-factory.com/
 * 
 * Copyright (c) 2002, The Measurement Factory, Inc.  All rights reserved.  See
 * the LICENSE file for details.
 */

#include <sys/types.h>
#include <sys/time.h>
#include <sys/stat.h>

#include <netinet/in.h>

#include <pcap.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <ctype.h>
#include <curses.h>
#include <assert.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>
#ifdef __APPLE__
#include <arpa/nameser_compat.h>
#endif

#include <sys/socket.h>
#include <net/if_arp.h>
#include <net/if.h>
#include <netinet/if_ether.h>

#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>
#include <netdb.h>

#include "hashtbl.h"
static hashkeycmp in_addr_cmp;
static hashfunc in_addr_hash;

#define PCAP_SNAPLEN 1460
#define MAX_QNAME_SZ 512
#ifndef ETHER_HDR_LEN
#define ETHER_ADDR_LEN 6
#define ETHER_TYPE_LEN 2
#define ETHER_HDR_LEN (ETHER_ADDR_LEN * 2 + ETHER_TYPE_LEN)
#endif
#ifndef ETHERTYPE_8021Q
#define ETHERTYPE_8021Q 0x8100
#endif
#ifndef ETHERTYPE_IPV6
#define ETHERTYPE_IPV6 0x86DD
#endif

#if USE_PPP
#include <net/if_ppp.h>
#define PPP_ADDRESS_VAL       0xff	/* The address byte value */
#define PPP_CONTROL_VAL       0x03	/* The control byte value */
#endif

#if defined(__linux__) || defined(__GLIBC__) || defined(__GNU__)
#define uh_dport dest
#define uh_sport source
#endif

typedef struct {
    struct in6_addr src;
    int count;
}      AgentAddr;

typedef struct {
    char *s;
    int count;
}      StringCounter;

typedef struct {
    struct in6_addr addr;
    char *str;
}      StringAddr;

/* This struct cobbles together Source and Sld */
typedef struct {
    StringAddr straddr;
    int count;
}      StringAddrCounter;

typedef struct {
    int cnt;
    void *ptr;
}      SortItem;

typedef struct _rfc1035_header rfc1035_header;
struct _rfc1035_header {
    unsigned short id;
    unsigned int qr:1;
    unsigned int opcode:4;
    unsigned int aa:1;
    unsigned int tc:1;
    unsigned int rd:1;
    unsigned int ra:1;
    unsigned int rcode:4;
    unsigned short qdcount;
    unsigned short ancount;
    unsigned short nscount;
    unsigned short arcount;
};

struct ip_list_s {
    struct in6_addr addr;
    void *data;
    struct ip_list_s *next;
};
typedef struct ip_list_s ip_list_t;

char *device = NULL;
pcap_t *pcap = NULL;
/*
 * bpf_program_str used to default to
 *   udp dst port 53 and udp[10:2] & 0x8000 = 0
 * but that didn't work so well with IPv6.  Now we have
 * the command line options -Q and -R to choose counting queries,
 * responses, or both.
 */
char *bpf_program_str = "udp port 53";
WINDOW *w;
static unsigned short port53;
void (*SubReport) (void)= NULL;
int (*handle_datalink) (const u_char * pkt, int len)= NULL;
int Quit = 0;
char *progname = NULL;
int anon_flag = 0;
int sld_flag = 0;
int nld_flag = 0;
int promisc_flag = 1;
ip_list_t *IgnoreList = NULL;
int do_redraw = 1;
int opt_count_queries = 0;
int opt_count_replies = 0;
int opt_count_ipv4 = 0;
int opt_count_ipv6 = 0;

/*
 * flags/features for non-interactive mode
 */
int interactive = 1;
typedef int (printer) (const char *,...);
printer *print_func = (printer *) printw;

#define T_MAX 65536
#ifndef T_A6
#define T_A6 38
#endif
#ifndef T_SRV
#define T_SRV 33
#endif
#define C_MAX 65536
#define OP_MAX 16

int query_count_intvl = 0;
int query_count_total = 0;
int reply_count_intvl = 0;
int reply_count_total = 0;
int qtype_counts[T_MAX];
int opcode_counts[OP_MAX];
int qclass_counts[C_MAX];
hashtbl *Sources = NULL;
hashtbl *Destinations = NULL;
hashtbl *Tlds = NULL;
hashtbl *Slds = NULL;
hashtbl *Nlds = NULL;
hashtbl *SSC2 = NULL;
hashtbl *SSC3 = NULL;
#ifdef __OpenBSD__
struct bpf_timeval last_ts;
#else
struct timeval last_ts;
#endif
time_t report_interval = 1;


/* Prototypes */
void SldBySource_report(void);
void NldBySource_report(void);
void Sources_report(void);
void Destinatioreport(void);
void Qtypes_report(void);
void Opcodes_report(void);
void Tld_report(void);
void Sld_report(void);
void Nld_report(void);
void Help_report(void);
void ResetCounters(void);
void report(void);

typedef int 
Filter_t(unsigned short,
    unsigned short,
    const char *,
    const struct in6_addr *,
    const struct in6_addr *);
Filter_t UnknownTldFilter;
Filter_t AforAFilter;
Filter_t RFC1918PtrFilter;
Filter_t *Filter = NULL;

#if defined(s6_addr32)
#elif defined(__FreeBSD__)
#define s6_addr32 __u6_addr.__u6_addr32
#elif defined(__NetBSD__)
#define s6_addr32 __u6_addr.__u6_addr32
#endif

int 
cmp_in6_addr(const struct in6_addr *a,
    const struct in6_addr *b)
{
    int i;

    for (i = 0; i < 4; i++)
	if (a->s6_addr32[i] != b->s6_addr32[i])
	    break;

    if (i >= 4)
	return (0);

    return (a->s6_addr32[i] > b->s6_addr32[i] ? 1 : -1);
}				/* int cmp_addrinfo */

inline int 
ignore_list_match(const struct in6_addr *addr)
{
    ip_list_t *ptr;

    for (ptr = IgnoreList; ptr != NULL; ptr = ptr->next)
	if (cmp_in6_addr(addr, &ptr->addr) == 0)
	    return (1);
    return (0);
}				/* int ignore_list_match */

void 
ignore_list_add(const struct in6_addr *addr)
{
    ip_list_t *new;

    if (ignore_list_match(addr) != 0)
	return;

    new = malloc(sizeof(ip_list_t));
    if (new == NULL) {
	perror("malloc");
	return;
    }
    memcpy(&new->addr, addr, sizeof(struct in6_addr));
    new->next = IgnoreList;

    IgnoreList = new;
}				/* void ignore_list_add */

void 
ignore_list_add_name(const char *name)
{
    struct addrinfo *ai_list;
    struct addrinfo *ai_ptr;
    struct in6_addr addr;
    int status;

    status = getaddrinfo(name, NULL, NULL, &ai_list);
    if (status != 0)
	return;

    for (ai_ptr = ai_list; ai_ptr != NULL; ai_ptr = ai_ptr->ai_next) {
	if (ai_ptr->ai_family == AF_INET) {
	    addr.s6_addr32[0] = 0;
	    addr.s6_addr32[1] = 0;
	    addr.s6_addr32[2] = htonl(0x0000FFFF);
	    addr.s6_addr32[3] = ((struct sockaddr_in *)ai_ptr->ai_addr)->sin_addr.s_addr;

	    ignore_list_add(&addr);
	} else {
	    ignore_list_add(&((struct sockaddr_in6 *)ai_ptr->ai_addr)->sin6_addr);
	}
    }				/* for */

    freeaddrinfo(ai_list);
}

void 
in6_addr_from_buffer(struct in6_addr *ia,
    const void *buf, size_t buf_len,
    int family)
{
    memset(ia, 0, sizeof(struct in6_addr));
    if ((AF_INET == family) && (sizeof(uint32_t) == buf_len)) {
	ia->s6_addr32[2] = htonl(0x0000FFFF);
	ia->s6_addr32[3] = *((uint32_t *) buf);
    } else if ((AF_INET6 == family) && (sizeof(struct in6_addr) == buf_len)) {
	memcpy(ia, buf, buf_len);
    }
}

void
allocate_anonymous_address(struct in6_addr *anon_addr,
    const struct in6_addr *orig_addr)
{
    static ip_list_t *list = NULL;
    static uint32_t next_num = 0;
    ip_list_t *ptr;

    memset(anon_addr, 0, sizeof(struct in6_addr));

    for (ptr = list; ptr != NULL; ptr = ptr->next) {
	if (cmp_in6_addr(orig_addr, &ptr->addr) == 0)
	    break;
    }

    if (ptr == NULL) {
	ptr = (ip_list_t *) malloc(sizeof(ip_list_t) + sizeof(uint32_t));
	if (ptr == NULL)
	    return;

	ptr->addr = *orig_addr;
	ptr->data = (void *)(ptr + 1);
	*((uint32_t *) ptr->data) = next_num;
	next_num++;

	ptr->next = list;
	list = ptr;
    }
    anon_addr->s6_addr32[3] = *((uint32_t *) ptr->data);
}

int
is_v4_in_v6(const struct in6_addr *addr)
{
	if (addr->s6_addr32[0])
		return 0;
	if (addr->s6_addr32[1])
		return 0;
	if (addr->s6_addr32[2] != ntohl(0x0000FFFF))
		return 0;
	return 1;
}

char *
anon_inet_ntoa(const struct in6_addr *addr)
{
    static char buffer[INET6_ADDRSTRLEN];
    struct in6_addr anon_addr;

    if (anon_flag) {
	allocate_anonymous_address(&anon_addr, addr);
	addr = &anon_addr;
    }
    if (is_v4_in_v6(addr)) {
	struct in_addr v4addr = {addr->s6_addr32[3]};

	if (inet_ntop(AF_INET, (const void *)&v4addr,
		buffer, sizeof(buffer)) == NULL)
	    return (NULL);
    } else {
	if (inet_ntop(AF_INET6, (const void *)addr,
		buffer, sizeof(buffer)) == NULL)
	    return (NULL);
    }

    return (buffer);
}

AgentAddr *
AgentAddr_lookup_or_add(hashtbl * tbl, struct in6_addr *addr)
{
    AgentAddr *x = hash_find(addr, tbl);
    if (NULL == x) {
	x = calloc(1, sizeof(*x));
	x->src = *addr;
	hash_add(&x->src, x, tbl);
    }
    return x;
}


static unsigned int
string_hash(const void *s)
{
    return SuperFastHash(s, strlen(s));
}

static int
string_cmp(const void *a, const void *b)
{
    return strcmp(a, b);
}

StringCounter *
StringCounter_lookup_or_add(hashtbl * tbl, const char *s)
{
    StringCounter *x = hash_find(s, tbl);
    if (NULL == x) {
	x = calloc(1, sizeof(*x));
	x->s = strdup(s);
	hash_add(x->s, x, tbl);
    }
    return x;
}

static unsigned int
stringaddr_hash(const void *p)
{
    const StringAddr *sa = p;
    unsigned int h1 = SuperFastHash(sa->str, strlen(sa->str));
    unsigned int h2 = SuperFastHash((void *)&sa->addr, 4);
    return h1 ^ h2;
}

static int
stringaddr_cmp(const void *a, const void *b)
{
    const StringAddr *A = a;
    const StringAddr *B = b;
    int x = strcmp(A->str, B->str);
    if (x)
	return x;
    return in_addr_cmp(&A->addr, &B->addr);
}

StringAddrCounter *
StringAddrCounter_lookup_or_add(hashtbl * tbl, const struct in6_addr *addr, const char *str)
{
    StringAddr sa;
    sa.addr = *addr;
    sa.str = (char *)str;
    StringAddrCounter *x = hash_find(&sa, tbl);
    if (NULL == x) {
	x = calloc(1, sizeof(*x));
	x->straddr.str = strdup(str);
	x->straddr.addr = *addr;
	hash_add(&x->straddr, x, tbl);
    }
    return x;
}

int
SortItem_cmp(const void *A, const void *B)
{
    const SortItem *a = A;
    const SortItem *b = B;
    if (a->cnt < b->cnt)
	return 1;
    if (a->cnt > b->cnt)
	return -1;
    if (a->ptr < b->ptr)
	return 1;
    if (a->ptr > b->ptr)
	return -1;
    return 0;
}

static unsigned int
in_addr_hash(const void *key)
{
    if (is_v4_in_v6(key))
    	return SuperFastHash(key+12, 4);
   return SuperFastHash(key, 16);
}

static int
in_addr_cmp(const void *a, const void *b)
{
    struct in_addr A = *(struct in_addr *)a;
    struct in_addr B = *(struct in_addr *)b;
    if (A.s_addr < B.s_addr)
	return -1;
    if (A.s_addr > B.s_addr)
	return 1;
    return 0;
}

#define RFC1035_MAXLABELSZ 63
static int
rfc1035NameUnpack(const char *buf, size_t sz, off_t * off, char *name, size_t ns
)
{
    off_t no = 0;
    unsigned char c;
    size_t len;
    assert(ns > 0);
    do {
	if ((*off) >= sz)
	    break;
	c = *(buf + (*off));
	if (c > 191) {
	    /* blasted compression */
	    unsigned short s;
	    off_t ptr;
	    memcpy(&s, buf + (*off), sizeof(s));
	    s = ntohs(s);
	    (*off) += sizeof(s);
	    /* Sanity check */
	    if ((*off) >= sz)
		return 1;
	    ptr = s & 0x3FFF;
	    /* Make sure the pointer is inside this message */
	    if (ptr >= sz)
		return 2;
	    return rfc1035NameUnpack(buf, sz, &ptr, name + no, ns - no);
	} else if (c > RFC1035_MAXLABELSZ) {
	    /*
	     * "(The 10 and 01 combinations are reserved for future use.)"
	     */
	    break;
	    return 3;
	} else {
	    (*off)++;
	    len = (size_t) c;
	    if (len == 0)
		break;
	    if (len > (ns - 1))
		len = ns - 1;
	    if ((*off) + len > sz)	/* message is too short */
		return 4;
	    memcpy(name + no, buf + (*off), len);
	    (*off) += len;
	    no += len;
	    *(name + (no++)) = '.';
	}
    } while (c > 0);
    *(name + no - 1) = '\0';
    /* make sure we didn't allow someone to overflow the name buffer */
    assert(no <= ns);
    return 0;
}

const char *
QnameToNld(const char *qname, int nld)
{
    const char *t = strrchr(qname, '.');
    int dotcount = 1;
    if (NULL == t)
	t = qname;
    if (0 == strcmp(t, ".arpa"))
	dotcount--;
    while (t > qname && dotcount < nld) {
	t--;
	if ('.' == *t)
	    dotcount++;
    }
    if (t > qname)
	t++;
    return t;
}

int
handle_dns(const char *buf, int len,
    const struct in6_addr *s_addr,
    const struct in6_addr *d_addr)
{
    rfc1035_header qh;
    unsigned short us;
    char qname[MAX_QNAME_SZ];
    unsigned short qtype;
    unsigned short qclass;
    off_t offset;
    char *t;
    const char *s;
    int x;
    StringCounter *sc;
    StringAddrCounter *ssc;

    if (len < sizeof(qh))
	return 0;

    memcpy(&us, buf + 00, 2);
    qh.id = ntohs(us);

    memcpy(&us, buf + 2, 2);
    us = ntohs(us);
    qh.qr = (us >> 15) & 0x01;
    if (0 == qh.qr && 0 == opt_count_queries)
	return 0;
    if (1 == qh.qr && 0 == opt_count_replies)
	return 0;
    qh.opcode = (us >> 11) & 0x0F;
    qh.aa = (us >> 10) & 0x01;
    qh.tc = (us >> 9) & 0x01;
    qh.rd = (us >> 8) & 0x01;
    qh.ra = (us >> 7) & 0x01;
    qh.rcode = us & 0x0F;

    memcpy(&us, buf + 4, 2);
    qh.qdcount = ntohs(us);

    memcpy(&us, buf + 6, 2);
    qh.ancount = ntohs(us);

    memcpy(&us, buf + 8, 2);
    qh.nscount = ntohs(us);

    memcpy(&us, buf + 10, 2);
    qh.arcount = ntohs(us);

    offset = sizeof(qh);
    memset(qname, '\0', MAX_QNAME_SZ);
    x = rfc1035NameUnpack(buf, len, &offset, qname, MAX_QNAME_SZ);
    if (0 != x)
	return 0;
    if ('\0' == qname[0])
	strcpy(qname, ".");
    while ((t = strchr(qname, '\n')))
	*t = ' ';
    while ((t = strchr(qname, '\r')))
	*t = ' ';
    for (t = qname; *t; t++)
	*t = tolower(*t);

    memcpy(&us, buf + offset, 2);
    qtype = ntohs(us);
    memcpy(&us, buf + offset + 2, 2);
    qclass = ntohs(us);

    if (Filter && 0 == Filter(qtype, qclass, qname, s_addr, d_addr))
	return 0;

    /* gather stats */
    qtype_counts[qtype]++;
    qclass_counts[qclass]++;
    opcode_counts[qh.opcode]++;

    s = QnameToNld(qname, 1);
    sc = StringCounter_lookup_or_add(Tlds, s);
    sc->count++;

    if (sld_flag) {
	s = QnameToNld(qname, 2);
	sc = StringCounter_lookup_or_add(Slds, s);
	sc->count++;

	/* increment StringAddrCounter */
	ssc = StringAddrCounter_lookup_or_add(SSC2, s_addr, s);
	ssc->count++;
    }
    if (nld_flag) {
	s = QnameToNld(qname, 3);
	sc = StringCounter_lookup_or_add(Nlds, s);
	sc->count++;

	/* increment StringAddrCounter */
	ssc = StringAddrCounter_lookup_or_add(SSC3, s_addr, s);
	ssc->count++;
    }
    if (0 == qh.qr) {
	query_count_intvl++;
	query_count_total++;
    } else {
	reply_count_intvl++;
	reply_count_total++;
    }
    return 1;
}

int
handle_udp(const struct udphdr *udp, int len,
    const struct in6_addr *s_addr,
    const struct in6_addr *d_addr)
{
    char buf[PCAP_SNAPLEN];
    if (port53 != udp->uh_dport && port53 != udp->uh_sport)
	return 0;
    memcpy(buf, udp + 1, len - sizeof(*udp));
    if (0 == handle_dns(buf, len - sizeof(*udp), s_addr, d_addr))
	return 0;
    return 1;
}

int
handle_ipv6(struct ip6_hdr *ipv6, int len)
{
    char buf[PCAP_SNAPLEN];
    int offset;
    int nexthdr;

    struct in6_addr s_addr;
    struct in6_addr d_addr;
    uint16_t payload_len;

    AgentAddr *agent;

    if (0 == opt_count_ipv6)
	return 0;

    offset = sizeof(struct ip6_hdr);
    nexthdr = ipv6->ip6_nxt;
    s_addr = ipv6->ip6_src;
    d_addr = ipv6->ip6_dst;
    payload_len = ntohs(ipv6->ip6_plen);

    if (ignore_list_match(&s_addr))
	return (0);

    /*
     * Parse extension headers. This only handles the standard headers, as
     * defined in RFC 2460, correctly. Fragments are discarded.
     */
    while ((IPPROTO_ROUTING == nexthdr)	/* routing header */
	||(IPPROTO_HOPOPTS == nexthdr)	/* Hop-by-Hop options. */
	||(IPPROTO_FRAGMENT == nexthdr)	/* fragmentation header. */
	||(IPPROTO_DSTOPTS == nexthdr)	/* destination options. */
	||(IPPROTO_DSTOPTS == nexthdr)	/* destination options. */
	||(IPPROTO_AH == nexthdr)	/* destination options. */
	||(IPPROTO_ESP == nexthdr)) {	/* encapsulating security payload. */
	struct ip6_ext ext_hdr;
	uint16_t ext_hdr_len;

	/* Catch broken packets */
	if ((offset + sizeof(struct ip6_ext)) > len)
	    return (0);

	/* Cannot handle fragments. */
	if (IPPROTO_FRAGMENT == nexthdr)
	    return (0);

	memcpy(&ext_hdr, (char *)ipv6 + offset, sizeof(struct ip6_ext));
	nexthdr = ext_hdr.ip6e_nxt;
	ext_hdr_len = (8 * (ntohs(ext_hdr.ip6e_len) + 1));

	/* This header is longer than the packets payload.. WTF? */
	if (ext_hdr_len > payload_len)
	    return (0);

	offset += ext_hdr_len;
	payload_len -= ext_hdr_len;
    }				/* while */

    /* Catch broken and empty packets */
    if (((offset + payload_len) > len)
	|| (payload_len == 0)
	|| (payload_len > PCAP_SNAPLEN))
	return (0);

    if (IPPROTO_UDP != nexthdr)
	return (0);

    memcpy(buf, (char *)ipv6 + offset, payload_len);
    if (handle_udp((struct udphdr *)buf, payload_len, &s_addr, &d_addr) == 0)
	return (0);

    if ((agent = AgentAddr_lookup_or_add(Sources, &s_addr)) != NULL)
	agent->count++;
    if ((agent = AgentAddr_lookup_or_add(Destinations, &d_addr)) != NULL)
	agent->count++;

    return (1);			/* Success */
}


int
handle_ipv4(const struct ip *ip, int len)
{
    char buf[PCAP_SNAPLEN];
    int offset = ip->ip_hl << 2;
    AgentAddr *clt;
    AgentAddr *srv;
    struct in6_addr s_addr;
    struct in6_addr d_addr;

    if (ip->ip_v == 6)
	return (handle_ipv6((struct ip6_hdr *)ip, len));

    if (0 == opt_count_ipv4)
	return 0;

    in6_addr_from_buffer(&s_addr, &ip->ip_src.s_addr, sizeof(ip->ip_src.s_addr), AF_INET);
    in6_addr_from_buffer(&d_addr, &ip->ip_dst.s_addr, sizeof(ip->ip_dst.s_addr), AF_INET);
    if (ignore_list_match(&s_addr))
	return (0);

    if (IPPROTO_UDP != ip->ip_p)
	return 0;
    memcpy(buf, (void *)ip + offset, len - offset);
    if (0 == handle_udp((struct udphdr *)buf, len - offset, &s_addr, &d_addr))
	return 0;
    clt = AgentAddr_lookup_or_add(Sources, &s_addr);
    clt->count++;
    srv = AgentAddr_lookup_or_add(Destinations, &d_addr);
    srv->count++;
    return 1;
}

#if USE_PPP
int
handle_ppp(const u_char * pkt, int len)
{
    char buf[PCAP_SNAPLEN];
    unsigned short us;
    unsigned short proto;
    if (len < 2)
	return 0;
    if (*pkt == PPP_ADDRESS_VAL && *(pkt + 1) == PPP_CONTROL_VAL) {
	pkt += 2;		/* ACFC not used */
	len -= 2;
    }
    if (len < 2)
	return 0;
    if (*pkt % 2) {
	proto = *pkt;		/* PFC is used */
	pkt++;
	len--;
    } else {
	memcpy(&us, pkt, sizeof(us));
	proto = ntohs(us);
	pkt += 2;
	len -= 2;
    }
    if (ETHERTYPE_IP != proto && PPP_IP != proto)
	return 0;
    memcpy(buf, pkt, len);
    return handle_ipv4((struct ip *)buf, len);
}

#endif

int
handle_null(const u_char * pkt, int len)
{
    unsigned int family;
    memcpy(&family, pkt, sizeof(family));
    if (AF_INET != family)
	return 0;
    return handle_ipv4((struct ip *)(pkt + 4), len - 4);
}

#ifdef DLT_LOOP
int
handle_loop(const u_char * pkt, int len)
{
    unsigned int family;
    memcpy(&family, pkt, sizeof(family));
    if (AF_INET != ntohl(family))
	return 0;
    return handle_ipv4((struct ip *)(pkt + 4), len - 4);
}

#endif

#ifdef DLT_RAW
int
handle_raw(const u_char * pkt, int len)
{
    return handle_ipv4((struct ip *)pkt, len);
}

#endif

int
handle_ether(const u_char * pkt, int len)
{
    char buf[PCAP_SNAPLEN];
    struct ether_header *e = (void *)pkt;
    unsigned short etype = ntohs(e->ether_type);
    if (len < ETHER_HDR_LEN)
	return 0;
    pkt += ETHER_HDR_LEN;
    len -= ETHER_HDR_LEN;
    if (ETHERTYPE_8021Q == etype) {
	etype = ntohs(*(unsigned short *)(pkt + 2));
	pkt += 4;
	len -= 4;
    }
    if ((ETHERTYPE_IP != etype) && (ETHERTYPE_IPV6 != etype))
	return 0;
    memcpy(buf, pkt, len);
    if (ETHERTYPE_IPV6 == etype)
	return (handle_ipv6((struct ip6_hdr *)buf, len));
    else
	return handle_ipv4((struct ip *)buf, len);
}

void
handle_pcap(u_char * udata, const struct pcap_pkthdr *hdr, const u_char * pkt)
{
    if (hdr->caplen < ETHER_HDR_LEN)
	return;
    if (0 == handle_datalink(pkt, hdr->caplen))
	return;
    last_ts = hdr->ts;
}

void
cron_pre(void)
{
    (void)0;
}

void
cron_post(void)
{
    query_count_intvl = 0;
    reply_count_intvl = 0;
}

void
redraw()
{
    cron_pre();
    report();
    cron_post();
    do_redraw = 0;
}

void
keyboard(void)
{
    int ch;
    int old_do_redraw = do_redraw;
    /*
     * The screen should be redrawn after any valid key is pressed.
     */
    do_redraw = 1;
    ch = getch() & 0xff;
    if (ch >= 'A' && ch <= 'Z')
	ch += 'a' - 'A';
    switch (ch) {
    case 's':
	SubReport = Sources_report;
	break;
    case 'd':
	SubReport = Destinatioreport;
	break;
    case '1':
	SubReport = Tld_report;
	break;
    case '2':
	SubReport = Sld_report;
	break;
    case '3':
	SubReport = Nld_report;
	break;
    case 'c':
    case '@':
	SubReport = SldBySource_report;
	break;
    case '#':
	SubReport = NldBySource_report;
	break;
    case 't':
	SubReport = Qtypes_report;
	break;
    case 'o':
	SubReport = Opcodes_report;
	break;
    case 030:
	Quit = 1;
	break;
    case 022:
	ResetCounters();
	break;
    case '?':
	SubReport = Help_report;
	break;
    case ' ':
	/* noop - just redraw the screen */
	break;
    default:
	do_redraw = old_do_redraw;
	break;
    }
}

void
gotsigalrm(int sig)
{
    do_redraw = 1;
}

void
Help_report(void)
{
    print_func(" s - Sources list\n");
    print_func(" d - Destinations list\n");
    print_func(" t - Query types\n");
    print_func(" o - Opcodes\n");
    print_func(" 1 - TLD list\n");
    print_func(" 2 - SLD list\n");
    print_func(" 3 - 3LD list\n");
    print_func(" @ - SLD+Sources list\n");
    print_func(" # - 3LD+Sources list\n");
    print_func("^R - Reset counters\n");
    print_func("^X - Exit\n");
    print_func("\n");
    print_func("? - this\n");
}

char *
qtype_str(int t)
{
    static char buf[30];
    switch (t) {
    case T_A:
	return "A?";
	break;
    case T_NS:
	return "NS?";
	break;
    case T_CNAME:
	return "CNAME?";
	break;
    case T_SOA:
	return "SOA?";
	break;
    case T_PTR:
	return "PTR?";
	break;
    case T_MX:
	return "MX?";
	break;
    case T_TXT:
	return "TXT?";
	break;
    case T_SIG:
	return "SIG?";
	break;
    case T_KEY:
	return "KEY?";
	break;
    case T_AAAA:
	return "AAAA?";
	break;
    case T_LOC:
	return "LOC?";
	break;
    case T_SRV:
	return "SRV?";
	break;
    case T_A6:
	return "A6?";
	break;
    case T_ANY:
	return "ANY?";
	break;
    default:
	snprintf(buf, 30, "#%d?", t);
	return buf;
    }
    /* NOTREACHED */
}

char *
opcode_str(int o)
{
    static char buf[30];
    switch (o) {
    case 0:
	return "Query";
	break;
    case 1:
	return "Iquery";
	break;
    case 2:
	return "Status";
	break;
    case 4:
	return "Notify";
	break;
    case 5:
	return "Update";
	break;
    default:
	snprintf(buf, 30, "Opcode%d", o);
	return buf;
    }
    /* NOTREACHED */
}

int
get_nlines(void)
{
    if (interactive)
	return getmaxy(w) - 6;
    else
	return 50;
}

void
StringCounter_report(hashtbl * tbl, char *what)
{
    int sortsize = hash_count(tbl);
    SortItem *sortme = calloc(sortsize, sizeof(SortItem));
    int i;
    StringCounter *sc;
    hash_iter_init(tbl);
    sortsize = 0;
    while ((sc = hash_iterate(tbl))) {
	sortme[sortsize].cnt = sc->count;
	sortme[sortsize].ptr = sc;
	sortsize++;
    }
    qsort(sortme, sortsize, sizeof(SortItem), SortItem_cmp);

    int nlines = get_nlines();
    print_func("%-30s %9s %6s\n", what, "count", "%");
    print_func("%-30s %9s %6s\n",
	"------------------------------", "---------", "------");
    for (i = 0; i < nlines && i < sortsize; i++) {
	sc = sortme[i].ptr;
	print_func("%-30.30s %9d %6.1f\n",
	    sc->s,
	    sc->count,
	    100.0 * sc->count / (query_count_total+reply_count_total));
    }

    free(sortme);
}

void
StringAddrCounter_free(void *p)
{
    StringAddrCounter *ssc = p;
    free(ssc->straddr.str);
}

void
Tld_report(void)
{
    StringCounter_report(Tlds, "TLD");
}

void
Sld_report(void)
{
    if (0 == sld_flag) {
	print_func("\tYou must start %s with the -s option\n", progname);
	print_func("\tto collect 2nd level domain stats.\n", progname);
    } else {
	StringCounter_report(Slds, "SLD");
    }
}
void
Nld_report(void)
{
    if (0 == nld_flag) {
	print_func("\tYou must start %s with the -t option\n", progname);
	print_func("\tto collect 3nd level domain stats.\n", progname);
    } else {
	StringCounter_report(Nlds, "3LD");
    }
}

void
Qtypes_report(void)
{
    int type;
    int nlines = get_nlines();
    print_func("%-10s %9s %6s\n", "Query Type", "count", "%");
    print_func("%-10s %9s %6s\n", "----------", "---------", "------");
    for (type = 0; type < T_MAX; type++) {
	if (0 == qtype_counts[type])
	    continue;
	print_func("%-10s %9d %6.1f\n",
	    qtype_str(type),
	    qtype_counts[type],
	    100.0 * qtype_counts[type] / (query_count_total+reply_count_total));
	if (0 == --nlines)
	    break;
    }
}

void
Opcodes_report(void)
{
    int op;
    int nlines = get_nlines();
    print_func("%-10s %9s %6s\n", "Opcode    ", "count", "%");
    print_func("%-10s %9s %6s\n", "----------", "---------", "------");
    for (op = 0; op < OP_MAX; op++) {
	if (0 == opcode_counts[op])
	    continue;
	print_func("%-10s %9d %6.1f\n",
	    opcode_str(op),
	    opcode_counts[op],
	    100.0 * opcode_counts[op] / (query_count_total+reply_count_total));
	if (0 == --nlines)
	    break;
    }
}

void
AgentAddr_report(hashtbl * tbl, const char *what)
{
    int sortsize = hash_count(tbl);
    SortItem *sortme = calloc(sortsize, sizeof(SortItem));
    int i;
    AgentAddr *a;
    hash_iter_init(tbl);
    sortsize = 0;
    while ((a = hash_iterate(tbl))) {
	sortme[sortsize].cnt = a->count;
	sortme[sortsize].ptr = a;
	sortsize++;
    }
    qsort(sortme, sortsize, sizeof(SortItem), SortItem_cmp);

    int nlines = get_nlines();
    print_func("%-40s %9s %6s\n", what, "count", "%");
    print_func("%-40s %9s %6s\n", "----------------", "---------", "------");
    for (i = 0; i < nlines && i < sortsize; i++) {
	a = sortme[i].ptr;
	print_func("%-40s %9d %6.1f\n",
	    anon_inet_ntoa(&a->src),
	    a->count,
	    100.0 * a->count / (query_count_total + reply_count_total));
    }

    free(sortme);
}

void
StringAddrCounter_report(hashtbl * tbl, char *what1, char *what2)
{
    int sortsize = hash_count(tbl);
    SortItem *sortme = calloc(sortsize, sizeof(SortItem));
    int i;
    StringAddrCounter *ssc;
    hash_iter_init(tbl);
    sortsize = 0;
    while ((ssc = hash_iterate(tbl))) {
	sortme[sortsize].cnt = ssc->count;
	sortme[sortsize].ptr = ssc;
	sortsize++;
    }
    qsort(sortme, sortsize, sizeof(SortItem), SortItem_cmp);

    int nlines = get_nlines();
    print_func("%-40s %-32s %9s %6s\n", what1, what2, "count", "%");
    print_func("%-40s %-32s %9s %6s\n",
	"----------------", "--------------------", "---------", "------");
    for (i = 0; i < nlines && i < sortsize; i++) {
	ssc = sortme[i].ptr;
	print_func("%-40s %-32s %9d %6.1f\n",
	    anon_inet_ntoa(&ssc->straddr.addr),
	    ssc->straddr.str,
	    ssc->count,
	    100.0 * ssc->count / (query_count_total+reply_count_total));
    }
}

void
SldBySource_report(void)
{
    if (0 == sld_flag) {
	print_func("\tYou must start %s with the -s option\n", progname);
	print_func("\tto collect 2nd level domain stats.\n", progname);
    } else {
	StringAddrCounter_report(SSC2, "Source", "SLD");
    }
}

void
NldBySource_report(void)
{
    if (0 == nld_flag) {
	print_func("\tYou must start %s with the -t option\n", progname);
	print_func("\tto collect 3nd level domain stats.\n", progname);
    } else {
	StringAddrCounter_report(SSC3, "Source", "3LD");
    }
}


void
Sources_report(void)
{
    AgentAddr_report(Sources, "Sources");
}

void
Destinatioreport(void)
{
    AgentAddr_report(Destinations, "Destinations");
}

void
report(void)
{
    int Y = 0;
    move(Y, 0);
    if (opt_count_queries) {
        print_func("Queries: %d new, %d total",
	    query_count_intvl, query_count_total);
        clrtoeol();
	Y++;
    }
    if (opt_count_replies) {
	move(Y, 0);
        print_func("Replies: %d new, %d total",
	    reply_count_intvl, reply_count_total);
        clrtoeol();
	Y++;
    }
    time_t t = time(NULL);
    move(0, 50);
    print_func("%s", ctime(&t));
    move(Y+1, 0);
    clrtobot();
    if (SubReport)
	SubReport();
    refresh();
}

/*
 * === BEGIN FILTERS ==========================================================
 */

#include "known_tlds.h"

int
UnknownTldFilter(unsigned short qt, unsigned short qc, const char *qn,
    const struct in6_addr *sip,
    const struct in6_addr *dip)
{
    const char *tld = QnameToNld(qn, 1);
    unsigned int i;
    if (NULL == tld)
	return 1;		/* tld is unknown */
    for (i = 0; KnownTLDS[i]; i++)
	if (0 == strcmp(KnownTLDS[i], tld))
	    return 0;		/* tld is known */
    return 1;			/* tld is unknown */
}

int
AforAFilter(unsigned short qt, unsigned short qc, const char *qn,
    const struct in6_addr *sip,
    const struct in6_addr *dip)
{
    struct in_addr a;
    if (qt != T_A)
	return 0;
    return inet_aton(qn, &a);
}

int
RFC1918PtrFilter(unsigned short qt, unsigned short qc, const char *qn,
    const struct in6_addr *sip,
    const struct in6_addr *dip)
{
    char *t;
    char q[128];
    unsigned int i = 0;
    if (qt != T_PTR)
	return 0;
    strncpy(q, qn, sizeof(q) - 1);
    q[sizeof(q) - 1] = '\0';
    t = strstr(q, ".in-addr.arpa");
    if (NULL == t)
	return 0;
    *t = '\0';
    for (t = strtok(q, "."); t; t = strtok(NULL, ".")) {
	i >>= 8;
	i |= ((atoi(t) & 0xff) << 24);
    }
    if ((i & 0xff000000) == 0x0a000000)
	return 1;
    if ((i & 0xfff00000) == 0xac100000)
	return 1;
    if ((i & 0xffff0000) == 0xc0a80000)
	return 1;
    return 0;
}

void
set_filter(const char *fn)
{
    if (0 == strcmp(fn, "unknown-tlds"))
	Filter = UnknownTldFilter;
    else if (0 == strcmp(fn, "A-for-A"))
	Filter = AforAFilter;
    else if (0 == strcmp(fn, "rfc1918-ptr"))
	Filter = RFC1918PtrFilter;
    else
	Filter = NULL;
}

/*
 * === END FILTERS ==========================================================
 */

void
init_curses(void)
{
    w = initscr();
    cbreak();
    noecho();
    nodelay(w, 1);
}

void
ResetCounters(void)
{
    if (NULL == Sources)
	Sources = hash_create(16384, in_addr_hash, in_addr_cmp);
    if (NULL == Destinations)
	Destinations = hash_create(16384, in_addr_hash, in_addr_cmp);
    if (NULL == Tlds)
	Tlds = hash_create(8192, string_hash, string_cmp);
    if (NULL == Slds)
	Slds = hash_create(8192, string_hash, string_cmp);
    if (NULL == Nlds)
	Nlds = hash_create(8192, string_hash, string_cmp);
    if (NULL == SSC2)
	SSC2 = hash_create(8192, stringaddr_hash, stringaddr_cmp);
    if (NULL == SSC3)
	SSC3 = hash_create(8192, stringaddr_hash, stringaddr_cmp);
    query_count_intvl = 0;
    query_count_total = 0;
    memset(qtype_counts, '\0', sizeof(qtype_counts));
    memset(qclass_counts, '\0', sizeof(qclass_counts));
    memset(opcode_counts, '\0', sizeof(opcode_counts));
    hash_free(Sources, free);
    hash_free(Destinations, free);
    hash_free(Tlds, free);
    hash_free(Slds, free);
    hash_free(Nlds, free);
    hash_free(SSC2, StringAddrCounter_free);
    hash_free(SSC3, StringAddrCounter_free);
    memset(&last_ts, '\0', sizeof(last_ts));
}

void
usage(void)
{
    fprintf(stderr, "usage: %s [opts] netdevice|savefile\n",
	progname);
    fprintf(stderr, "\t-a\tAnonymize IP Addrs\n");
    fprintf(stderr, "\t-b expr\tBPF program code\n");
    fprintf(stderr, "\t-i addr\tIgnore this source IP address\n");
    fprintf(stderr, "\t-p\tDon't put interface in promiscuous mode\n");
    fprintf(stderr, "\t-r\tRedraw interval, in seconds\n");
    fprintf(stderr, "\t-s\tEnable 2nd level domain stats collection\n");
    fprintf(stderr, "\t-t\tEnable 3nd level domain stats collection\n");
    fprintf(stderr, "\t-f\tfilter-name\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "Available filters:\n");
    fprintf(stderr, "\tunknown-tlds\n");
    fprintf(stderr, "\tA-for-A\n");
    fprintf(stderr, "\trfc1918-ptr\n");
    exit(1);
}

int
pcap_select(pcap_t * p, int sec, int usec)
{
    fd_set R;
    struct timeval to;
    FD_ZERO(&R);
    FD_SET(pcap_fileno(p), &R);
    to.tv_sec = sec;
    to.tv_usec = usec;
    return select(pcap_fileno(p) + 1, &R, NULL, NULL, &to);
}

int
main(int argc, char *argv[])
{
    char errbuf[PCAP_ERRBUF_SIZE];
    int x;
    struct stat sb;
    int readfile_state = 0;
    int redraw_interval = 1;
    struct itimerval redraw_itv;
    struct bpf_program fp;

    port53 = htons(53);
    SubReport = Sources_report;
    progname = strdup(strrchr(argv[0], '/') ? strchr(argv[0], '/') + 1 : argv[0]);
    srandom(time(NULL));
    ResetCounters();

    while ((x = getopt(argc, argv, "46ab:f:i:pr:stQR")) != -1) {
	switch (x) {
	case '4':
	    opt_count_ipv4 = 1;
	    break;
	case '6':
	    opt_count_ipv6 = 1;
	    break;
	case 'a':
	    anon_flag = 1;
	    break;
	case 's':
	    sld_flag = 1;
	    break;
	case 't':
	    nld_flag = 1;
	    break;
	case 'p':
	    promisc_flag = 0;
	    break;
	case 'b':
	    bpf_program_str = strdup(optarg);
	    break;
	case 'i':
	    ignore_list_add_name(optarg);
	    break;
	case 'f':
	    set_filter(optarg);
	    break;
	case 'r':
	    redraw_interval = atoi(optarg);
	    break;
	case 'Q':
	    opt_count_queries = 1;
	    break;
	case 'R':
	    opt_count_replies = 1;
	    break;
	default:
	    usage();
	    break;
	}
    }
    argc -= optind;
    argv += optind;

    if (argc < 1)
	usage();
    device = strdup(argv[0]);

    if (0 == opt_count_queries && 0 == opt_count_replies)
	opt_count_queries = 1;

    if (0 == opt_count_ipv4 && 0 == opt_count_ipv6)
	opt_count_ipv4 = opt_count_ipv6 = 1;

    if (0 == stat(device, &sb))
	readfile_state = 1;
    if (readfile_state) {
	pcap = pcap_open_offline(device, errbuf);
    } else {
	pcap = pcap_open_live(device, PCAP_SNAPLEN, promisc_flag, 1000, errbuf);
    }
    if (NULL == pcap) {
	fprintf(stderr, "pcap_open_*: %s\n", errbuf);
	exit(1);
    }
    if (0 == isatty(1)) {
	if (0 == readfile_state) {
	    fprintf(stderr, "Non-interactive mode requires savefile argument\n");
	    exit(1);
	}
	interactive = 0;
	print_func = printf;
    }
    memset(&fp, '\0', sizeof(fp));
    x = pcap_compile(pcap, &fp, bpf_program_str, 1, 0);
    if (x < 0) {
	fprintf(stderr, "pcap_compile failed\n");
	exit(1);
    }
    x = pcap_setfilter(pcap, &fp);
    if (x < 0) {
	fprintf(stderr, "pcap_setfilter failed\n");
	exit(1);
    }
    /*
     * non-blocking call added for Mac OS X bugfix.  Sent by Max Horn. ref
     * http://www.tcpdump.org/lists/workers/2002/09/msg00033.html
     */
    x = pcap_setnonblock(pcap, 1, errbuf);
    if (x < 0) {
	fprintf(stderr, "pcap_setnonblock failed: %s\n", errbuf);
	exit(1);
    }
    switch (pcap_datalink(pcap)) {
    case DLT_EN10MB:
	handle_datalink = handle_ether;
	break;
#if USE_PPP
    case DLT_PPP:
	handle_datalink = handle_ppp;
	break;
#endif
#ifdef DLT_LOOP
    case DLT_LOOP:
	handle_datalink = handle_loop;
	break;
#endif
#ifdef DLT_RAW
    case DLT_RAW:
	handle_datalink = handle_raw;
	break;
#endif
    case DLT_NULL:
	handle_datalink = handle_null;
	break;
    default:
	fprintf(stderr, "unsupported data link type %d\n",
	    pcap_datalink(pcap));
	return 1;
	break;
    }
    if (interactive) {
	init_curses();
	redraw();

	if (redraw_interval) {
	    signal(SIGALRM, gotsigalrm);
	    redraw_itv.it_interval.tv_sec = redraw_interval;
	    redraw_itv.it_interval.tv_usec = 0;
	    redraw_itv.it_value.tv_sec = redraw_interval;
	    redraw_itv.it_value.tv_usec = 0;
	    setitimer(ITIMER_REAL, &redraw_itv, NULL);
	}
	while (0 == Quit) {
	    if (readfile_state < 2) {
		/*
		 * On some OSes select() might return 0 even when there are
		 * packets to process.  Thus, we always ignore its return value
		 * and just call pcap_dispatch() anyway.
		 */
		if (0 == readfile_state)	/* interactive */
		    pcap_select(pcap, 1, 0);
		x = pcap_dispatch(pcap, 50, handle_pcap, NULL);
	    }
	    if (0 == x && 1 == readfile_state) {
		/* block on keyboard until user quits */
		readfile_state++;
		nodelay(w, 0);
	    }
	    keyboard();
	    if (do_redraw || 0 == redraw_interval)
		redraw();
	}
	endwin();		/* klin, Thu Nov 28 08:56:51 2002 */
    } else {
	while (pcap_dispatch(pcap, 50, handle_pcap, NULL))
	    (void)0;
	cron_pre();
	Sources_report();
	print_func("\n");
	Destinatioreport();
	print_func("\n");
	Qtypes_report();
	print_func("\n");
	Opcodes_report();
	print_func("\n");
	Tld_report();
	print_func("\n");
	Sld_report();
	print_func("\n");
	Nld_report();
	print_func("\n");
	SldBySource_report();
    }

    pcap_close(pcap);
    return 0;
}
