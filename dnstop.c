/*
 * $Id$
 * 
 * http://dnstop.measurement-factory.com/
 * 
 * Copyright (c) 2002, The Measurement Factory, Inc.  All rights reserved.  See
 * the LICENSE file for details.
 */

static const char *Version = "@VERSION@";

#include "config.h"

#include <sys/types.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <netinet/in.h>

#include <err.h>
#include <errno.h>
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
#ifdef HAVE_ARPA_NAMESER_COMPAT_H
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

#ifdef HAVE_NET_IF_PPP_H
#include <net/if_ppp.h>
#define PPP_ADDRESS_VAL       0xff	/* The address byte value */
#define PPP_CONTROL_VAL       0x03	/* The control byte value */
#endif

#include "hashtbl.h"
#include "inX_addr.h"

#define PCAP_SNAPLEN 65535
#define MAX_QNAME_SZ 512
#define DNS_MSG_HDR_SZ 12
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

#if defined(__linux__) || defined(__GLIBC__) || defined(__GNU__)
#define uh_dport dest
#define uh_sport source
#endif

typedef struct {
    inX_addr src;
    int count;
    int prevcount;
    int maxdelta;
    long avgadd;
    int avgct;
}      AgentAddr;

typedef struct {
    char *s;
    int count;
}      StringCounter;

typedef struct {
    inX_addr addr;
    char *str;
}      StringAddr;

/* This struct cobbles together Source and Nld */
typedef struct {
    StringAddr straddr;
    int count;
}      StringAddrCounter;

typedef struct {
    int cnt;
    int delta;
    double avgdelta;
    int maxdelta;
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
    inX_addr addr;
    void *data;
    struct ip_list_s *next;
};
typedef struct ip_list_s ip_list_t;

char *device = NULL;
pcap_t *pcap = NULL;
/*
 * bpf_program_str used to default to:
 * 
 * udp dst port 53 and udp[10:2] & 0x8000 = 0
 * 
 * but that didn't work so well with IPv6.  Now we have the command line options
 * -Q and -R to choose counting queries, responses, or both.
 */
char *bpf_program_str = "udp port 53";
WINDOW *w;
static unsigned short check_port = 0;
void (*SubReport) (void)= NULL;
int (*handle_datalink) (const u_char * pkt, int len)= NULL;
int Quit = 0;
int Got_EOF = 0;
unsigned int hash_buckets = 100057;
char *progname = NULL;
int anon_flag = 0;
int max_level = 2;
int cur_level = 1;
int show_delta = 1;
int sort_maxdelta = 0;
int sort_avgdelta = 0;
int promisc_flag = 1;
int progress_flag = 0;
ip_list_t *IgnoreList = NULL;
int do_redraw = 1;
int opt_count_queries = 0;
int opt_count_replies = 0;
int opt_count_ipv4 = 0;
int opt_count_ipv6 = 0;
int opt_count_domsrc = 1;
const char *opt_filter_by_name = 0;

/*
 * flags/features for non-interactive mode
 */
int interactive = 1;
typedef int (printer) (const char *,...);
printer *print_func = (printer *) printw;

typedef const char *(col_fmt) (const SortItem *);
typedef char *(strify) (unsigned int);

#define T_MAX 65536
#define C_MAX 65536
#define OP_MAX 16
#define RC_MAX 16

unsigned int query_count_intvl = 0;
unsigned int query_count_total = 0;
unsigned int reply_count_intvl = 0;
unsigned int reply_count_total = 0;

int qtype_counts[T_MAX];
int opcode_counts[OP_MAX];
int rcode_counts[RC_MAX];
int qclass_counts[C_MAX];

hashtbl *Sources = NULL;
hashtbl *Destinations = NULL;
hashtbl *Domains[10];
hashtbl *DomSrcs[10];
hashtbl *KnownTLDs = NULL;
hashtbl *NewGTLDs = NULL;

#ifdef HAVE_STRUCT_BPF_TIMEVAL
struct bpf_timeval last_ts;
#else
struct timeval last_ts;
#endif
time_t report_interval = 1;

/*
 * These hold "%d" printfed strings for non-standard types/codes
 */
static char *qtypes_buf[T_MAX];
static char *rcodes_buf[RC_MAX];
static char *opcodes_buf[OP_MAX];

/* Prototypes */
void Sources_report(void);
void Destinatioreport(void);
void Qtypes_report(void);
void Opcodes_report(void);
void Rcodes_report(void);
void Domain_report();
void DomSrc_report();
void Help_report(void);
void ResetCounters(void);
void report(void);

typedef struct {
    unsigned short qtype;
    unsigned short qclass;
    const char *qname;
    const inX_addr *src_addr;
    const inX_addr *dst_addr;
    unsigned char rcode;
}      FilterData;

typedef int Filter_t(FilterData *);
Filter_t UnknownTldFilter;
Filter_t AforAFilter;
Filter_t RFC1918PtrFilter;
Filter_t RcodeRefusedFilter;
Filter_t QnameFilter;
Filter_t BitsquatFilter;
Filter_t QtypeAnyFilter;
Filter_t *Filter = NULL;

unsigned int
my_inXaddr_hash(const void *key)
{
    return inXaddr_hash(key, 24);
}

int
my_inXaddr_cmp(const void *a, const void *b)
{
    return inXaddr_cmp(a, b);
}

int
ignore_list_match(const inX_addr * addr)
{
    ip_list_t *ptr;

    for (ptr = IgnoreList; ptr != NULL; ptr = ptr->next)
	if (0 == inXaddr_cmp(addr, &ptr->addr))
	    return (1);
    return (0);
}

void
ignore_list_add(const inX_addr * addr)
{
    ip_list_t *new;
    if (ignore_list_match(addr) != 0)
	return;
    new = malloc(sizeof(ip_list_t));
    if (new == NULL) {
	perror("malloc");
	return;
    }
    new->addr = *addr;
    new->next = IgnoreList;
    IgnoreList = new;
}

void
ignore_list_add_name(const char *name)
{
    struct addrinfo *ai_list;
    struct addrinfo *ai_ptr;
    inX_addr addr;
    int status;
    status = getaddrinfo(name, NULL, NULL, &ai_list);
    if (status != 0)
	return;
    for (ai_ptr = ai_list; ai_ptr != NULL; ai_ptr = ai_ptr->ai_next) {
	if (ai_ptr->ai_family == AF_INET) {
	    inXaddr_assign_v4(&addr, &((struct sockaddr_in *)ai_ptr->ai_addr)->
		sin_addr);
	    ignore_list_add(&addr);
	}
#if USE_IPV6
	else if (ai_ptr->ai_family == AF_INET6) {
	    inXaddr_assign_v6(&addr, &((struct sockaddr_in6 *)ai_ptr->ai_addr)->sin6_addr);
	    ignore_list_add(&addr);
	}
#endif
    }
    freeaddrinfo(ai_list);
}

void
allocate_anonymous_address(inX_addr * anon_addr, const inX_addr * orig_addr)
{
    static ip_list_t *list = NULL;
    static int entropy_fd = -1;
    ip_list_t *ptr;

    for (ptr = list; ptr != NULL; ptr = ptr->next) {
	if (0 == inXaddr_cmp(orig_addr, &ptr->addr))
	    break;
    }

    if (-1 == entropy_fd) {
	entropy_fd = open("/dev/urandom", 0);
	if (-1 == entropy_fd) {
	    entropy_fd = open("/dev/random", 0);
	    if (-1 == entropy_fd) {
		fprintf(stderr, "failed to open /dev/urandom or /dev/random");
		exit(1);
	    }
	}
    }
    if (ptr == NULL) {
	char buf[16];
	ptr = (ip_list_t *) malloc(sizeof(ip_list_t) + sizeof(inX_addr));
	if (ptr == NULL)
	    return;
	ptr->addr = *orig_addr;
	ptr->data = (void *)(ptr + 1);
	if (4 == inXaddr_version(orig_addr)) {
	    ssize_t rd = read(entropy_fd, buf, 4);
	    if (rd < 4)
		err(errno, "read entropy");
	    inXaddr_assign_v4(ptr->data, (struct in_addr *)buf);
	}
#if USE_IPV6
	else {
	    ssize_t rd = read(entropy_fd, buf, 16);
	    if (rd < 16)
		err(errno, "read entropy");
	    inXaddr_assign_v6(ptr->data, (struct in6_addr *)buf);
	}
#endif
	ptr->next = list;
	list = ptr;
    }
    *anon_addr = *(inX_addr *) ptr->data;
}

const char *
anon_inet_ntoa(const inX_addr * addr)
{
    static char buffer[INET6_ADDRSTRLEN];
    inX_addr anon_addr;
    if (anon_flag) {
	allocate_anonymous_address(&anon_addr, addr);
	addr = &anon_addr;
    }
    return inXaddr_ntop(addr, buffer, sizeof(buffer));
}

AgentAddr *
AgentAddr_lookup_or_add(hashtbl * tbl, const inX_addr * addr)
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
    return hashendian(s, strlen(s), 0);
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
    unsigned int h0 = inXaddr_hash(&sa->addr, 32);
    unsigned int h1 = hashendian(sa->str, strlen(sa->str), h0);
    return h1;
}

static int
stringaddr_cmp(const void *a, const void *b)
{
    const StringAddr *A = a;
    const StringAddr *B = b;
    int x = inXaddr_cmp(&A->addr, &B->addr);
    if (x)
	return x;
    return strcmp(A->str, B->str);
}

StringAddrCounter *
StringAddrCounter_lookup_or_add(hashtbl * tbl, const inX_addr * addr, const char *str)
{
    StringAddr sa;
    StringAddrCounter *x;
    sa.addr = *addr;
    sa.str = (char *)str;
    x = hash_find(&sa, tbl);
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
    if (sort_maxdelta) {
        if (a->maxdelta < b->maxdelta) return 1;
        if (a->maxdelta > b->maxdelta) return -1;
    }
    if (sort_avgdelta) {
        if (a->avgdelta < b->avgdelta) return 1;
        if (a->avgdelta > b->avgdelta) return -1;
    }
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

#define RFC1035_MAXLABELSZ 63
static int
rfc1035NameUnpack(const char *buf, size_t sz, off_t * off, char *name, size_t ns
)
{
    off_t no = 0;
    unsigned char c;
    size_t len;
    static int loop_detect = 0;
    if (loop_detect > 2)
	return 4;		/* compression loop */
    if (ns <= 0)
	return 4;		/* probably compression loop */
    do {
	if ((*off) >= sz)
	    break;
	c = *(buf + (*off));
	if (c > 191) {
	    /* blasted compression */
	    int rc;
	    unsigned short s;
	    off_t ptr;
	    memcpy(&s, buf + (*off), sizeof(s));
	    s = ntohs(s);
	    (*off) += sizeof(s);
	    /* Sanity check */
	    if ((*off) >= sz)
		return 1;	/* message too short */
	    ptr = s & 0x3FFF;
	    /* Make sure the pointer is inside this message */
	    if (ptr >= sz)
		return 2;	/* bad compression ptr */
	    if (ptr < DNS_MSG_HDR_SZ)
		return 2;	/* bad compression ptr */
	    loop_detect++;
	    rc = rfc1035NameUnpack(buf, sz, &ptr, name + no, ns - no);
	    loop_detect--;
	    return rc;
	} else if (c > RFC1035_MAXLABELSZ) {
	    /*
	     * "(The 10 and 01 combinations are reserved for future use.)"
	     */
	    return 3;		/* reserved label/compression flags */
	    break;
	} else {
	    (*off)++;
	    len = (size_t) c;
	    if (len == 0)
		break;
	    if (len > (ns - 1))
		len = ns - 1;
	    if ((*off) + len > sz)
		return 4;	/* message is too short */
	    if (no + len + 1 > ns)
		return 5;	/* qname would overflow name buffer */
	    memcpy(name + no, buf + (*off), len);
	    (*off) += len;
	    no += len;
	    *(name + (no++)) = '.';
	}
    } while (c > 0);
    if (no > 0)
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

char *
str_tolower(char *s)
{
    char *t;
    for (t = s; *t; t++)
	*t = tolower(*t);
    return s;
}

int
handle_dns(const char *buf, int len,
    const inX_addr * src_addr,
    const inX_addr * dst_addr)
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
    AgentAddr *agent;
    int lvl;

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
    str_tolower(qname);

    memcpy(&us, buf + offset, 2);
    qtype = ntohs(us);
    memcpy(&us, buf + offset + 2, 2);
    qclass = ntohs(us);

    if (Filter) {
	FilterData fd;
	fd.qtype = qtype;
	fd.qclass = qclass;
	fd.qname = qname;
	fd.src_addr = src_addr;
	fd.dst_addr = dst_addr;
	fd.rcode = qh.rcode;
	if (0 == Filter(&fd))
	    return 0;
    }
    /* gather stats */
    if (0 == opt_count_replies || 1 == qh.qr) {
	rcode_counts[qh.rcode]++;
        if ((agent = AgentAddr_lookup_or_add(Destinations, dst_addr)) != NULL)
	    agent->count++;
    }
    if (0 == opt_count_queries || 0 == qh.qr) {
	qtype_counts[qtype]++;
	qclass_counts[qclass]++;
	opcode_counts[qh.opcode]++;
        if ((agent = AgentAddr_lookup_or_add(Sources, src_addr)) != NULL)
	    agent->count++;
	for (lvl = 1; lvl <= max_level; lvl++) {
	    s = QnameToNld(qname, lvl);
	    sc = StringCounter_lookup_or_add(Domains[lvl], s);
	    sc->count++;
	    if (opt_count_domsrc) {
		StringAddrCounter *ssc;
		ssc = StringAddrCounter_lookup_or_add(DomSrcs[lvl], src_addr, s);
		ssc->count++;
	    }
	}
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
    const inX_addr * src_addr,
    const inX_addr * dst_addr)
{
    if (check_port && check_port != udp->uh_dport && check_port != udp->uh_sport)
	return 0;
    if (0 == handle_dns((char *)(udp + 1), len - sizeof(*udp), src_addr, dst_addr))
	return 0;
    return 1;
}

#if USE_IPV6
int
handle_ipv6(struct ip6_hdr *ipv6, int len)
{
    int offset;
    int nexthdr;

    inX_addr src_addr;
    inX_addr dst_addr;
    uint16_t payload_len;


    if (0 == opt_count_ipv6)
	return 0;

    offset = sizeof(struct ip6_hdr);
    nexthdr = ipv6->ip6_nxt;
    inXaddr_assign_v6(&src_addr, &ipv6->ip6_src);
    inXaddr_assign_v6(&dst_addr, &ipv6->ip6_dst);
    payload_len = ntohs(ipv6->ip6_plen);

    if (ignore_list_match(&src_addr))
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
	struct {
	    uint8_t nexthdr;
	    uint8_t length;
	}      ext_hdr;
	uint16_t ext_hdr_len;

	/* Catch broken packets */
	if ((offset + sizeof(ext_hdr)) > len)
	    return (0);

	/* Cannot handle fragments. */
	if (IPPROTO_FRAGMENT == nexthdr)
	    return (0);

	memcpy(&ext_hdr, (char *)ipv6 + offset, sizeof(ext_hdr));
	nexthdr = ext_hdr.nexthdr;
	ext_hdr_len = (8 * (ntohs(ext_hdr.length) + 1));

	/* This header is longer than the packets payload.. WTF? */
	if (ext_hdr_len > payload_len)
	    return (0);

	offset += ext_hdr_len;
	payload_len -= ext_hdr_len;
    }				/* while */

    /* Catch broken and empty packets */
    if (((offset + payload_len) > len)
	|| (payload_len == 0))
	return (0);

    if (IPPROTO_UDP != nexthdr)
	return (0);

    if (handle_udp((struct udphdr *)((char *)ipv6 + offset), payload_len, &src_addr, &dst_addr) == 0)
	return (0);

    return (1);			/* Success */
}
#endif


int
handle_ipv4(const struct ip *ip, int len)
{
    int offset = ip->ip_hl << 2;
    inX_addr src_addr;
    inX_addr dst_addr;

#if USE_IPV6
    if (ip->ip_v == 6)
	return (handle_ipv6((struct ip6_hdr *)ip, len));
#endif

    if (0 == opt_count_ipv4)
	return 0;

    inXaddr_assign_v4(&src_addr, &ip->ip_src);
    inXaddr_assign_v4(&dst_addr, &ip->ip_dst);
    if (ignore_list_match(&src_addr))
	return (0);

    if (IPPROTO_UDP != ip->ip_p)
	return 0;
    if (0 == handle_udp((struct udphdr *)((char *)ip + offset), len - offset, &src_addr, &dst_addr))
	return 0;
    return 1;
}

#ifdef HAVE_NET_IF_PPP_H
int
handle_ppp(const u_char * pkt, int len)
{
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
    return handle_ipv4((struct ip *)pkt, len);
}
#endif

int
handle_null(const u_char * pkt, int len)
{
    unsigned int family;
    memcpy(&family, pkt, sizeof(family));
    if (AF_INET == family)
	return handle_ipv4((struct ip *)(pkt + 4), len - 4);
#if USE_IPV6
    if (AF_INET6 == family)
	return handle_ipv6((struct ip6_hdr *)(pkt + 4), len - 4);
#endif
    return 0;
}

#ifdef DLT_LOOP
int
handle_loop(const u_char * pkt, int len)
{
    unsigned int family;
    memcpy(&family, pkt, sizeof(family));
    if (AF_INET == ntohl(family))
	return handle_ipv4((struct ip *)(pkt + 4), len - 4);
#if USE_IPV6
    if (AF_INET6 == ntohl(family))
	return handle_ipv6((struct ip6_hdr *)(pkt + 4), len - 4);
#endif
    return 0;
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
handle_ip(const u_char * pkt, int len, unsigned short etype)
{
#if USE_IPV6
    if (ETHERTYPE_IPV6 == etype) {
	return (handle_ipv6((struct ip6_hdr *)pkt, len));
    } else
#endif
    if (ETHERTYPE_IP == etype) {
	return handle_ipv4((struct ip *)pkt, len);
    }
    return 0;
}

int
handle_ether(const u_char * pkt, int len)
{
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
    return handle_ip(pkt, len, etype);
}

#ifdef DLT_LINUX_SLL
static int
handle_linux_sll(const u_char * pkt, int len)
{
    struct sll_header {
	uint16_t pkt_type;
	uint16_t dev_type;
	uint16_t addr_len;
	uint8_t addr[8];
	uint16_t proto_type;
    }         *hdr;
    uint16_t etype;

    if (len < sizeof(struct sll_header))
	return (0);

    hdr = (struct sll_header *)pkt;
    pkt = (u_char *) (hdr + 1);
    len -= sizeof(struct sll_header);

    etype = ntohs(hdr->proto_type);
    return handle_ip(pkt, len, etype);
}
#endif				/* DLT_LINUX_SLL */

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
    case 'e':
        show_delta = show_delta ? 0 : 1;
        break;
    case 'a':
        sort_avgdelta = sort_avgdelta ? 0 : 1;
        sort_maxdelta = 0;
	break;
    case 'm':
        sort_maxdelta = sort_maxdelta ? 0 : 1;
        sort_avgdelta = 0;
        break;
    case '1':
    case '2':
    case '3':
    case '4':
    case '5':
    case '6':
    case '7':
    case '8':
    case '9':
	SubReport = Domain_report;
	cur_level = ch - '0';
	break;
    case '!':
	SubReport = DomSrc_report;
	cur_level = 1;
	break;
    case 'c':
    case '@':
	SubReport = DomSrc_report;
	cur_level = 2;
	break;
    case '#':
	SubReport = DomSrc_report;
	cur_level = 3;
	break;
    case '$':
	SubReport = DomSrc_report;
	cur_level = 4;
	break;
    case '%':
	SubReport = DomSrc_report;
	cur_level = 5;
	break;
    case '^':
	SubReport = DomSrc_report;
	cur_level = 6;
	break;
    case '&':
	SubReport = DomSrc_report;
	cur_level = 7;
	break;
    case '*':
	SubReport = DomSrc_report;
	cur_level = 8;
	break;
    case '(':
	SubReport = DomSrc_report;
	cur_level = 9;
	break;
    case 't':
	SubReport = Qtypes_report;
	break;
    case 'o':
	SubReport = Opcodes_report;
	break;
    case 'r':
	SubReport = Rcodes_report;
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
    signal(sig, gotsigalrm);
}

void
Help_report(void)
{
    print_func(" s - Sources list\n");
    print_func(" d - Destinations list\n");
    print_func(" e - Toggle display of delta\n");
    print_func(" a - Toggle sorting by average delta\n");
    print_func(" m - Toggle sorting by maximum delta\n");
    print_func(" t - Query types\n");
    print_func(" o - Opcodes\n");
    print_func(" r - Rcodes\n");
    print_func(" 1 - 1st level Query Names"
	"\t! - with Sources\n");
    print_func(" 2 - 2nd level Query Names"
	"\t@ - with Sources\n");
    print_func(" 3 - 3rd level Query Names"
	"\t# - with Sources\n");
    print_func(" 4 - 4th level Query Names"
	"\t$ - with Sources\n");
    print_func(" 5 - 5th level Query Names"
	"\t%% - with Sources\n");
    print_func(" 6 - 6th level Query Names"
	"\t^ - with Sources\n");
    print_func(" 7 - 7th level Query Names"
	"\t& - with Sources\n");
    print_func(" 8 - 8th level Query Names"
	"\t* - with Sources\n");
    print_func(" 9 - 9th level Query Names"
	"\t( - with Sources\n");
    print_func("^R - Reset counters\n");
    print_func("^X - Exit\n");
    print_func("\n");
    print_func(" ? - this\n");
}

char *
qtype_str(unsigned int t)
{
    char buf[30];
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
    case 13:
	return "HINFO?";
	break;
    case T_MX:
	return "MX?";
	break;
    case T_TXT:
	return "TXT?";
	break;
    case 18:
	return "AFSDB?";
	break;
    case T_SIG:
	return "SIG?";
	break;
    case T_KEY:
	return "KEY?";
	break;
    case 26:
	return "PX?";
	break;
    case T_AAAA:
	return "AAAA?";
	break;
    case T_LOC:
	return "LOC?";
	break;
    case 33:
	return "SRV?";
	break;
    case 35:
	return "NAPTR?";
	break;
    case 38:
	return "A6?";
	break;
    case 41:
	return "OPT?";
	break;
    case 43:
	return "DS?";
	break;
    case 44:
	return "SSHFP?";
	break;
    case 46:
	return "RRSIG?";
	break;
    case 47:
	return "NSEC?";
	break;
    case 48:
	return "DNSKEY?";
	break;
    case 50:
	return "NSEC3?";
	break;
    case 51:
	return "NSEC3PARAM?";
	break;
    case 52:
	return "TLSA?";
	break;
    case 99:
	return "SPF?";
	break;
    case T_ANY:
	return "ANY?";
	break;
    case 32769:
	return "DLV?";
	break;
    default:
	if (qtypes_buf[t])
	    return qtypes_buf[t];
	snprintf(buf, sizeof(buf), "#%u?", t);
	return qtypes_buf[t] = strdup(buf);
    }
    /* NOTREACHED */
}

char *
opcode_str(unsigned int o)
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
	if (opcodes_buf[o])
	    return opcodes_buf[o];
	snprintf(buf, 30, "Opcode%d", o);
	return opcodes_buf[o] = strdup(buf);
    }
    /* NOTREACHED */
}

char *
rcode_str(unsigned int r)
{
    static char buf[30];
    switch (r) {
    case 0:
	return "Noerror";
	break;
    case 1:
	return "Formerr";
	break;
    case 2:
	return "Servfail";
	break;
    case 3:
	return "Nxdomain";
	break;
    case 4:
	return "Notimpl";
	break;
    case 5:
	return "Refused";
	break;
    case 6:
	return "Yxdomain";
	break;
    case 7:
	return "Yxrrset";
	break;
    case 8:
	return "Nxrrset";
	break;
    case 9:
	return "Notauth";
	break;
    case 10:
	return "Notzone";
	break;
    default:
	if (rcodes_buf[r])
	    return rcodes_buf[r];
	snprintf(buf, 30, "Rcode%d", r);
	return rcodes_buf[r] = strdup(buf);
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

int
get_ncols(void)
{
    if (interactive)
	return getmaxx(w);
    else
	return 80;
}

const char *
StringCounter_col_fmt(const SortItem * si)
{
    StringCounter *sc = si->ptr;
    return sc->s;
}

const char *
dashes(int n)
{
    static char *buf = "-----------------------------------------------"
    "-----------------------------------------------------------------"
    "-----------------------------------------------------------------"
    "-----------------------------------------------------------------"
    "-----------------------------------------------------------------"
    "-----------------------------------------------------------------";
    return &buf[strlen(buf) - n];
}

void
Table_report(SortItem * sorted, int rows, const char *col1, const char *col2, col_fmt F1, col_fmt F2, unsigned int base)
{
    int W1 = strlen(col1);
    int W2 = col2 ? strlen(col2) : 0;
    int WC = 9;			/* width of "Count" column */
    int WP = 6;			/* width of "Percent" column */
    int WD = 8;			/* width of "Delta" column */
    int WA = 8;         /* width of "AvgDeleta" column */
    int WM = 8;			/* width of "MaxDelta" column */
    int i;
    int nlines = get_nlines();
    int ncols = get_ncols();
    char fmt1[64];
    char fmt2[64];
    unsigned int sum = 0;

    if (nlines > rows)
	nlines = rows;

    for (i = 0; i < nlines; i++) {
	const char *t = F1(sorted + i);
	if (W1 < strlen(t))
	    W1 = strlen(t);
    }
    if (W1 + 1 + WC + 1 + WP + 1 + WP + 1 > ncols)
	W1 = ncols - 1 - WC - 1 - WP - 1 - WP - 1;

    if (NULL == col2 || NULL == F2) {
    if (show_delta)
    {
        if (W1 + 1 + WC + 1 + WP + 1 + WP + 1 + WD + 1 + WA + 1 + WM + 1 > ncols)
        W1 = ncols - 1 - WC - 1 - WP - 1 - WP - 1 - WD - 1 - WA - 1 - WM - 1;

        snprintf(fmt1, 64, "%%-%d.%ds %%%ds %%%ds %%%ds %%%ds %%%ds %%%ds\n", W1, W1, WC, WP, WP, WD, WA, WM);
    	snprintf(fmt2, 64, "%%-%d.%ds %%%dd %%%d.1f %%%d.1f %%%dd %%%d.1f %%%dd\n", W1, W1, WC, WP, WP, WD, WA, WM);
    	print_func(fmt1, col1, "Count", "%", "cum%", "Delta", "AvgDelta", "MaxDelta");
    	print_func(fmt1, dashes(W1), dashes(WC), dashes(WP), dashes(WP), dashes(WD), dashes(WA), dashes(WM));
    	for (i = 0; i < nlines; i++) {
    	    sum += (sorted + i)->cnt;
    	    const char *t = F1(sorted + i);
    	    print_func(fmt2,
    		t,
    		(sorted + i)->cnt,
    		100.0 * (sorted + i)->cnt / base,
    		100.0 * sum / base,
            (sorted + i)->delta,
            (sorted + i)->avgdelta,
            (sorted + i)->maxdelta);
    	}
    }
    else
    {
    	snprintf(fmt1, 64, "%%-%d.%ds %%%ds %%%ds %%%ds\n", W1, W1, WC, WP, WP);
    	snprintf(fmt2, 64, "%%-%d.%ds %%%dd %%%d.1f %%%d.1f\n", W1, W1, WC, WP, WP);
    	print_func(fmt1, col1, "Count", "%", "cum%");
    	print_func(fmt1, dashes(W1), dashes(WC), dashes(WP), dashes(WP));
    	for (i = 0; i < nlines; i++) {
    	    sum += (sorted + i)->cnt;
    	    const char *t = F1(sorted + i);
    	    print_func(fmt2,
    		t,
    		(sorted + i)->cnt,
    		100.0 * (sorted + i)->cnt / base,
    		100.0 * sum / base);
    	}
    }
    } else {
	for (i = 0; i < nlines; i++) {
	    const char *t = F2(sorted + i);
	    if (W2 < strlen(t))
		W2 = strlen(t);
	}
	if (W2 + 1 + W1 + 1 + WC + 1 + WP + 1 + WP + 1 > ncols)
	    W2 = ncols - 1 - W1 - 1 - WC - 1 - WP - 1 - WP - 1;
	snprintf(fmt1, 64, "%%-%d.%ds %%-%d.%ds %%%ds %%%ds %%%ds\n", W1, W1, W2, W2, WC, WP, WP);
	snprintf(fmt2, 64, "%%-%d.%ds %%-%d.%ds %%%dd %%%d.1f %%%d.1f\n", W1, W1, W2, W2, WC, WP, WP);
	print_func(fmt1, col1, col2, "Count", "%", "cum%");
	print_func(fmt1, dashes(W1), dashes(W2), dashes(WC), dashes(WP), dashes(WP));
	for (i = 0; i < nlines; i++) {
	    const char *t = F1(sorted + i);
	    const char *q = F2(sorted + i);
	    sum += (sorted + i)->cnt;
	    print_func(fmt2,
		t,
		q,
		(sorted + i)->cnt,
		100.0 * (sorted + i)->cnt / base,
		100.0 * sum / base);
	}
    }
}

void
StringCounter_report(hashtbl * tbl, char *what)
{
    unsigned int sum = 0;
    int sortsize = hash_count(tbl);
    SortItem *sortme = calloc(sortsize, sizeof(SortItem));
    StringCounter *sc;
    hash_iter_init(tbl);
    sortsize = 0;
    while ((sc = hash_iterate(tbl))) {
	sum += sc->count;
	sortme[sortsize].cnt = sc->count;
	sortme[sortsize].ptr = sc;
	sortsize++;
    }
    qsort(sortme, sortsize, sizeof(SortItem), SortItem_cmp);
    Table_report(sortme, sortsize,
	what, NULL,
	StringCounter_col_fmt, NULL,
	sum);
    free(sortme);
}

void
StringAddrCounter_free(void *p)
{
    StringAddrCounter *ssc = p;
    free(ssc->straddr.str);
}

void
Domain_report(void)
{
    if (cur_level > max_level) {
	print_func("\tYou must start %s with -l %d\n", progname, cur_level);
	print_func("\tto collect this level of domain stats.\n", progname);
	return;
    }
    StringCounter_report(Domains[cur_level], "Query Name");
}

const char *
Qtype_col_fmt(const SortItem * si)
{
    return si->ptr;
}

void
Simple_report(int a[], unsigned int max, const char *name, strify * to_str)
{
    unsigned int i;
    unsigned int sum = 0;
    unsigned int sortsize = 0;
    SortItem *sortme = calloc(max, sizeof(SortItem));
    for (i = 0; i < max; i++) {
	if (0 >= a[i])
	    continue;
	sum += a[i];
	sortme[sortsize].cnt = a[i];
	sortme[sortsize].ptr = to_str(i);
	sortsize++;
    }
    qsort(sortme, sortsize, sizeof(SortItem), SortItem_cmp);
    Table_report(sortme, sortsize,
	name, NULL,
	Qtype_col_fmt, NULL,
	sum);
    free(sortme);
}

void
Qtypes_report(void)
{
    Simple_report(qtype_counts, T_MAX, "Query Type", qtype_str);
}

void
Opcodes_report(void)
{
    Simple_report(opcode_counts, OP_MAX, "Opcode", opcode_str);
}

void
Rcodes_report(void)
{
    Simple_report(rcode_counts, RC_MAX, "Rcode", rcode_str);
}

const char *
AgentAddr_col_fmt(const SortItem * si)
{
    AgentAddr *a = si->ptr;
    return anon_inet_ntoa(&a->src);
}

void
AgentAddr_report(hashtbl * tbl, const char *what)
{
    unsigned int sum = 0;
    unsigned int delta = 0;
    int sortsize = hash_count(tbl);
    SortItem *sortme = calloc(sortsize, sizeof(SortItem));
    AgentAddr *a;
    hash_iter_init(tbl);
    sortsize = 0;
    while ((a = hash_iterate(tbl))) {
	sum += a->count;
	delta = a->count - a->prevcount;
	if (delta>a->maxdelta) a->maxdelta = delta;
        a->prevcount = a->count;
        if (delta > 0) {
            a->avgadd += delta;
            a->avgct++;
        }
        sortme[sortsize].cnt = a->count;
        sortme[sortsize].delta = delta;
        if (a->avgct > 0)
            sortme[sortsize].avgdelta = (double) a->avgadd / (double) a->avgct;
        else
            sortme[sortsize].avgdelta = 0;
        sortme[sortsize].maxdelta = a->maxdelta;
        sortme[sortsize].ptr = a;
        sortsize++;
    }
    qsort(sortme, sortsize, sizeof(SortItem), SortItem_cmp);
    Table_report(sortme, sortsize,
	what, NULL,
	AgentAddr_col_fmt, NULL,
	sum);
    free(sortme);
}

const char *
StringAddr_col1_fmt(const SortItem * si)
{
    StringAddrCounter *ssc = si->ptr;
    return anon_inet_ntoa(&ssc->straddr.addr);
}

const char *
StringAddr_col2_fmt(const SortItem * si)
{
    StringAddrCounter *ssc = si->ptr;
    return ssc->straddr.str;
}



void
StringAddrCounter_report(hashtbl * tbl, char *what1, char *what2)
{
    unsigned int sum = 0;
    int sortsize = hash_count(tbl);
    SortItem *sortme = calloc(sortsize, sizeof(SortItem));
    StringAddrCounter *ssc;
    hash_iter_init(tbl);
    sortsize = 0;
    while ((ssc = hash_iterate(tbl))) {
	sum += ssc->count;
	sortme[sortsize].cnt = ssc->count;
	sortme[sortsize].ptr = ssc;
	sortsize++;
    }
    qsort(sortme, sortsize, sizeof(SortItem), SortItem_cmp);
    Table_report(sortme, sortsize,
	what1, what2,
	StringAddr_col1_fmt, StringAddr_col2_fmt,
	sum);
    free(sortme);
}

void
DomSrc_report(void)
{
    if (0 == opt_count_domsrc) {
	print_func("\tReport disabled\n");
	return;
    }
    if (cur_level > max_level) {
	print_func("\tYou must start %s with -l %d\n", progname, cur_level);
	print_func("\tto collect this level of domain stats.\n", progname);
	return;
    }
    StringAddrCounter_report(DomSrcs[cur_level], "Source", "Query Name");
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
    time_t t;
    move(Y, 0);
    if (opt_count_queries) {
	print_func("Queries: %u new, %u total",
	    query_count_intvl, query_count_total);
	if (Got_EOF)
	    print_func(", EOF");
	clrtoeol();
	Y++;
    }
    if (opt_count_replies) {
	move(Y, 0);
	print_func("Replies: %u new, %u total",
	    reply_count_intvl, reply_count_total);
	if (Got_EOF)
	    print_func(", EOF");
	clrtoeol();
	Y++;
    }
    t = time(NULL);
    move(0, get_ncols() - 25);
    print_func("%s", ctime(&t));
    move(Y + 1, 0);
    clrtobot();
    if (SubReport)
	SubReport();
    refresh();
}

/*
 * === BEGIN FILTERS ==========================================================
 */

#include "known_tlds.h"
#include "new_gtlds.h"

void
array_to_hash(const char *array[], hashtbl *hash)
{
	int i;
	for (i = 0; array[i]; i++) {
		char *s = strdup(array[i]);
		assert(s);
		str_tolower(s);
		hash_add(s, s, hash);
	}
}

int
UnknownTldFilter(FilterData * fd)
{
    const char *tld = QnameToNld(fd->qname, 1);
    if (NULL == tld)
	return 1;		/* tld is unknown */
    if (hash_find(tld, KnownTLDs))
	return 0;		/* tld is known */
    return 1;			/* tld is unknown */
}

int
NewGTldFilter(FilterData * fd)
{
    const char *tld = QnameToNld(fd->qname, 1);
    if (NULL == tld)
	return 0;		/* tld is unknown */
    if (hash_find(tld, NewGTLDs))
	return 1;		/* tld is new */
    return 0;			/* tld is old */
}

int
AforAFilter(FilterData * fd)
{
    struct in_addr a;
    if (fd->qtype != T_A)
	return 0;
    return inet_aton(fd->qname, &a);
}

int
RFC1918PtrFilter(FilterData * fd)
{
    char *t;
    char q[128];
    unsigned int i = 0;
    if (fd->qtype != T_PTR)
	return 0;
    strncpy(q, fd->qname, sizeof(q) - 1);
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

int
RcodeRefusedFilter(FilterData * fd)
{
    return REFUSED == fd->rcode ? 1 : 0;
}

int
QnameFilter(FilterData * fd)
{
    const char *F = opt_filter_by_name;
    const char *Q = fd->qname;
    size_t fo = strlen(F);
    size_t qo = strlen(Q);
    while (qo && fo)
	if (tolower(Q[--qo]) != tolower(F[--fo]))
	    return 0;
    if (fo)
	return 0;		/* didn't match all of opt_filter_by_name */
    if (0 == qo)
	return 1;		/* exact match */
    if ('.' == Q[qo - 1])
	return 1;		/* matched on domain boundary */
    return 0;
}

const char* BitsquatNames[] = {
	"FACEBOOK",
	"GOOGLE",
	"YAHOO",
	"YOUTUBE",
	"BLOGGER",
	NULL
};

int
BitsquatFilter(FilterData * fd)
{
    char sld[10];
    const char *s = QnameToNld(fd->qname, 2);
    int i;
    int j;
    if (0 == s)
	return 0;
    strncpy(sld, s, sizeof(sld));
    sld[sizeof(sld)-1] = 0;
    if (!strtok(sld, "."))
	return 0;
    for (j=0; BitsquatNames[j]; j++)
	if (0 == strcasecmp(sld, BitsquatNames[j]))
	    return 0;
    for (i=0; sld[i]; i++) {
	int k;
	int save = sld[i];
	for (k=0; k<8; k++) {
	    if (5==k)		// upper/lower case bit
		continue;
	    int m = 1<<k;
	    if (sld[i] & m)
		sld[i] &= ~m;
	    else
		sld[i] |= m;
	    for (j=0; BitsquatNames[j]; j++)
		if (0 == strcasecmp(sld, BitsquatNames[j]))
		    return 1;
	    sld[i] = save;
	}
    }
    return 0;
}

int
QtypeAnyFilter(FilterData *fd)
{
	return fd->qtype == T_ANY;
}

void
set_filter(const char *fn)
{
    if (0 == strcmp(fn, "unknown-tlds"))
	Filter = UnknownTldFilter;
    if (0 == strcmp(fn, "new-gtlds"))
	Filter = NewGTldFilter;
    else if (0 == strcmp(fn, "A-for-A"))
	Filter = AforAFilter;
    else if (0 == strcmp(fn, "rfc1918-ptr"))
	Filter = RFC1918PtrFilter;
    else if (0 == strcmp(fn, "refused"))
	Filter = RcodeRefusedFilter;
    else if (0 == strcmp(fn, "qname"))
	Filter = QnameFilter;
    else if (0 == strcmp(fn, "bitsquat"))
	Filter = BitsquatFilter;
    else if (0 == strcmp(fn, "qtype-any"))
	Filter = QtypeAnyFilter;
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
    int lvl;
    if (NULL == Sources)
	Sources = hash_create(hash_buckets, my_inXaddr_hash, my_inXaddr_cmp);
    if (NULL == Destinations)
	Destinations = hash_create(hash_buckets, my_inXaddr_hash, my_inXaddr_cmp);
    for (lvl = 1; lvl <= max_level; lvl++) {
	if (NULL != Domains[lvl])
	    continue;
	Domains[lvl] = hash_create(hash_buckets, string_hash, string_cmp);
	if (opt_count_domsrc)
	    DomSrcs[lvl] = hash_create(hash_buckets, stringaddr_hash, stringaddr_cmp);
    }
    query_count_intvl = 0;
    query_count_total = 0;
    reply_count_intvl = 0;
    reply_count_total = 0;
    memset(qtype_counts, 0, sizeof(qtype_counts));
    memset(qclass_counts, 0, sizeof(qclass_counts));
    memset(opcode_counts, 0, sizeof(opcode_counts));
    memset(rcode_counts, 0, sizeof(rcode_counts));
    hash_free(Sources, free);
    hash_free(Destinations, free);
    for (lvl = 1; lvl <= max_level; lvl++) {
	hash_free(Domains[lvl], free);
	if (opt_count_domsrc)
	    hash_free(DomSrcs[lvl], StringAddrCounter_free);
    }
    memset(&last_ts, '\0', sizeof(last_ts));
}

void
usage(void)
{
    fprintf(stderr, "usage: %s [opts] netdevice|savefile\n",
	progname);
    fprintf(stderr, "\t-4\tCount IPv4 packets\n");
    fprintf(stderr, "\t-6\tCount IPv6 packets\n");
    fprintf(stderr, "\t-Q\tCount queries\n");
    fprintf(stderr, "\t-R\tCount responses\n");
    fprintf(stderr, "\t-a\tAnonymize IP Addrs\n");
    fprintf(stderr, "\t-b expr\tBPF program code\n");
    fprintf(stderr, "\t-i addr\tIgnore this source IP address\n");
    fprintf(stderr, "\t-n name\tCount only messages in this domain\n");
    fprintf(stderr, "\t-p\tDon't put interface in promiscuous mode\n");
    fprintf(stderr, "\t-P\tPrint \"progress\" messages in non-interactive mode\n");
    fprintf(stderr, "\t-r\tRedraw interval, in seconds\n");
    fprintf(stderr, "\t-l N\tEnable domain stats up to N components\n");
    fprintf(stderr, "\t-X\tDon't tabulate the \"source + query name\" stats\n");
    fprintf(stderr, "\t-f\tfilter-name\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "Available filters:\n");
    fprintf(stderr, "\tunknown-tlds\n");
    fprintf(stderr, "\tnew-gtlds\n");
    fprintf(stderr, "\tA-for-A\n");
    fprintf(stderr, "\trfc1918-ptr\n");
    fprintf(stderr, "\trefused\n");
    fprintf(stderr, "\tqtype-any\n");
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

struct timeval start = {0, 0};
struct timeval now = {0, 0};
struct timeval last_progress = {0, 0};

void
progress(pcap_t * p)
{
    unsigned int msgs = query_count_total + reply_count_total;
    gettimeofday(&now, NULL);
    if (now.tv_sec == last_progress.tv_sec)
	return;
    time_t wall_elapsed = now.tv_sec - start.tv_sec;
    if (0 == wall_elapsed)
	return;
    double rate = (double)msgs / wall_elapsed;
    fprintf(stderr, "%u %7.1f m/s\n", msgs, rate);
    last_progress = now;
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

    SubReport = Sources_report;
    progname = strdup(strrchr(argv[0], '/') ? strchr(argv[0], '/') + 1 : argv[0]);
    srandom(time(NULL));
    memset(qtypes_buf, 0, sizeof(qtypes_buf));
    memset(rcodes_buf, 0, sizeof(rcodes_buf));
    memset(opcodes_buf, 0, sizeof(opcodes_buf));

    KnownTLDs = hash_create(hash_buckets, string_hash, string_cmp);
    NewGTLDs = hash_create(hash_buckets, string_hash, string_cmp);
    array_to_hash(KnownTLDs_array, KnownTLDs);
    array_to_hash(NewGTLDs_array, NewGTLDs);

    while ((x = getopt(argc, argv, "46ab:B:f:i:l:n:pPr:QRvVX")) != -1) {
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
	    max_level = 2;
	    break;
	case 't':
	    max_level = 3;
	    break;
	case 'l':
	    max_level = atoi(optarg);
	    if (max_level < 1 || max_level > 9)
		usage();
	    break;
	case 'n':
	    opt_filter_by_name = strdup(optarg);
	    set_filter("qname");
	    break;
	case 'p':
	    promisc_flag = 0;
	    break;
	case 'P':
	    progress_flag = 1;
	    break;
	case 'b':
	    bpf_program_str = strdup(optarg);
	    break;
	case 'B':
	    hash_buckets = atoi(optarg);
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
	case 'v':
	case 'V':
	    fprintf(stderr, "dnstop Version: %s\n", Version);
	    fprintf(stderr, "http://dnstop.measurement-factory.com/\n");
	    exit(0);
	case 'X':
	    opt_count_domsrc = 0;
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

    if (!strstr(bpf_program_str, "port "))
    	check_port = htons(53);
    if (0 == opt_count_queries && 0 == opt_count_replies)
	opt_count_queries = 1;

    if (0 == opt_count_ipv4 && 0 == opt_count_ipv6)
	opt_count_ipv4 = opt_count_ipv6 = 1;

    if (RcodeRefusedFilter == Filter) {
	opt_count_queries = 0;
	opt_count_replies = 1;
    }

    if (0 == stat(device, &sb))
	readfile_state = 1;
    if (readfile_state) {
	pcap = pcap_open_offline(device, errbuf);
    } else {
	pcap = pcap_open_live(device, PCAP_SNAPLEN, promisc_flag, 1, errbuf);
    }
    if (NULL == pcap) {
	fprintf(stderr, "pcap_open_*: %s\n", errbuf);
	exit(1);
    }
    if (0 == isatty(1) || 0 == isatty(0)) {
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
     *
     * UPDATE: pcap_setnonblock fails on OpenBSD.  Since this was a MacOS
     * workaround and dnstop does not require non-blocking, we'll won't
     * check the return status.
     */
    pcap_setnonblock(pcap, 1, errbuf);
    switch (pcap_datalink(pcap)) {
    case DLT_EN10MB:
	handle_datalink = handle_ether;
	break;
#ifdef DLT_PPP
#ifdef HAVE_NET_IF_PPP_H
    case DLT_PPP:
	handle_datalink = handle_ppp;
	break;
#endif
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
#ifdef DLT_LINUX_SLL
    case DLT_LINUX_SLL:
	handle_datalink = handle_linux_sll;
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

    ResetCounters();
    gettimeofday(&start, NULL);

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
		do_redraw = 1;
		Got_EOF = 1;
	    }
	    if (do_redraw || 0 == redraw_interval)
		redraw();
	    keyboard();
	}
	endwin();		/* klin, Thu Nov 28 08:56:51 2002 */
    } else {
	while (pcap_dispatch(pcap, 1, handle_pcap, NULL)) {
	    if (progress_flag && 0 == ((query_count_total + reply_count_total) & 0x3ff))
		progress(pcap);
	}
	cron_pre();
	Sources_report();
	print_func("\n");
	Destinatioreport();
	print_func("\n");
	Qtypes_report();
	print_func("\n");
	Opcodes_report();
	print_func("\n");
	Rcodes_report();
	for (cur_level = 1; cur_level <= max_level; cur_level++) {
	    print_func("\n");
	    Domain_report();
	}
	for (cur_level = 1; opt_count_domsrc && cur_level <= max_level; cur_level++) {
	    print_func("\n");
	    DomSrc_report();
	}
    }

    pcap_close(pcap);
    return 0;
}
