/* $Id$ */

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
#include <ctype.h>
#include <curses.h>
#include <assert.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <net/ethernet.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/udp.h>

#define PCAP_SNAPLEN 1460
#define MAX_QNAME_SZ 512

#ifdef __linux__
#define uh_dport dest
#endif

typedef struct _AgentAddr AgentAddr;
struct _AgentAddr {
    struct in_addr src;
    int count;
    AgentAddr *next;
};

typedef struct _StringCounter StringCounter;
struct _StringCounter {
    char *s;
    int count;
    StringCounter *next;
};

typedef struct _foo foo;
struct _foo {
    int cnt;
    void *ptr;
};

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

typedef struct _AnonMap AnonMap;
struct _AnonMap {
    struct in_addr real;
    struct in_addr anon;
    AnonMap *next;
};

char *device = NULL;
struct in_addr ignore_addr;
pcap_t *pcap = NULL;
char *bpf_program_str = "udp dst port 53";
WINDOW *w = NULL;
static unsigned short port53;
void (*SubReport) (void) = NULL;
int Quit = 0;
char *progname = NULL;
int anon_flag = 0;
int sld_flag = 0;
int promisc_flag = 1;
AnonMap *Anons = NULL;

#define T_MAX 65536
#define C_MAX 65536

int query_count_intvl = 0;
int query_count_total = 0;
int qtype_counts[T_MAX];
int qclass_counts[C_MAX];
AgentAddr *Sources = NULL;
AgentAddr *Destinations = NULL;
StringCounter *Tlds = NULL;
StringCounter *Slds = NULL;
struct timeval last_ts;

void Sources_report(void);
void Destinatioreport(void);
void Qtypes_report(void);
void Tld_report(void);
void Sld_report(void);
void Help_report(void);
void ResetCounters(void);

struct in_addr
AnonMap_lookup_or_add(AnonMap ** headP, struct in_addr real)
{
    AnonMap **T;
    for (T = headP; (*T); T = &(*T)->next)
	if ((*T)->real.s_addr == real.s_addr)
	    return (*T)->anon;
    (*T) = calloc(1, sizeof(**T));
    (*T)->real = real;
    (*T)->anon.s_addr = random();
    return (*T)->anon;
}

char *
anon_inet_ntoa(struct in_addr a)
{
    if (anon_flag)
	a = AnonMap_lookup_or_add(&Anons, a);
    return inet_ntoa(a);
}

AgentAddr *
AgentAddr_lookup_or_add(AgentAddr ** headP, struct in_addr a)
{
    AgentAddr **T;
    for (T = headP; (*T); T = &(*T)->next)
	if ((*T)->src.s_addr == a.s_addr)
	    return (*T);
    (*T) = calloc(1, sizeof(**T));
    (*T)->src = a;
    return (*T);
}

StringCounter *
StringCounter_lookup_or_add(StringCounter ** headP, const char *s)
{
    StringCounter **T;
    for (T = headP; (*T); T = &(*T)->next)
	if (0 == strcmp((*T)->s, s))
	    return (*T);
    (*T) = calloc(1, sizeof(**T));
    (*T)->s = strdup(s);
    return (*T);
}

int
foo_cmp(const void *A, const void *B)
{
    const foo *a = A;
    const foo *b = B;
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

void
AgentAddr_sort(AgentAddr ** headP)
{
    foo *sortme;
    int n_agents = 0;
    int i;
    AgentAddr *a;
    for (a = *headP; a; a = a->next)
	n_agents++;
    sortme = calloc(n_agents, sizeof(foo));
    n_agents = 0;
    for (a = *headP; a; a = a->next) {
	sortme[n_agents].cnt = a->count;
	sortme[n_agents].ptr = a;
	n_agents++;
    }
    qsort(sortme, n_agents, sizeof(foo), foo_cmp);
    for (i = 0; i < n_agents; i++) {
	*headP = sortme[i].ptr;
	headP = &(*headP)->next;
    }
    free(sortme);
    *headP = NULL;
}

void
StringCounter_sort(StringCounter ** headP)
{
    foo *sortme;
    int n_things = 0;
    int i;
    StringCounter *sc;
    for (sc = *headP; sc; sc = sc->next)
	n_things++;
    sortme = calloc(n_things, sizeof(foo));
    n_things = 0;
    for (sc = *headP; sc; sc = sc->next) {
	sortme[n_things].cnt = sc->count;
	sortme[n_things].ptr = sc;
	n_things++;
    }
    qsort(sortme, n_things, sizeof(foo), foo_cmp);
    for (i = 0; i < n_things; i++) {
	*headP = sortme[i].ptr;
	headP = &(*headP)->next;
    }
    free(sortme);
    *headP = NULL;
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

int
handle_dns(const char *buf, int len)
{
    rfc1035_header qh;
    unsigned short us;
    char qname[MAX_QNAME_SZ];
    unsigned short qtype;
    unsigned short qclass;
    off_t offset;
    char *t;
    int x;
    StringCounter *sc;

    if (len < sizeof(qh))
	return 0;

    memcpy(&us, buf + 00, 2);
    qh.id = ntohs(us);

    memcpy(&us, buf + 2, 2);
    qh.qr = (us >> 15) & 0x01;
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

    /* gather stats */
    qtype_counts[qtype]++;
    qclass_counts[qclass]++;

    t = strrchr(qname, '.');
    if (NULL == t)
	t = qname;
    if (t > qname)
	t++;
    sc = StringCounter_lookup_or_add(&Tlds, t);
    sc->count++;

    if (sld_flag) {
	int dotcount = 0;
	while (t > qname && dotcount < 2) {
		t--;
		if ('.' == *t)
			dotcount++;
	}
        if (t > qname)
	    t++;
	sc = StringCounter_lookup_or_add(&Slds, t);
	sc->count++;
    }

    return 1;
}

int
handle_udp(const struct udphdr *udp, int len)
{
    char buf[PCAP_SNAPLEN];
    if (port53 != udp->uh_dport)
	return 0;
    memcpy(buf, udp + 1, len - sizeof(*udp));
    if (0 == handle_dns(buf, len - sizeof(*udp)))
	return 0;
    return 1;
}

int
handle_ip(const struct ip *ip, int len)
{
    char buf[PCAP_SNAPLEN];
    int offset = ip->ip_hl << 2;
    AgentAddr *clt;
    AgentAddr *srv;
    if (ignore_addr.s_addr)
	if (ip->ip_src.s_addr == ignore_addr.s_addr)
	    return 0;
    if (IPPROTO_UDP != ip->ip_p)
	return 0;
    memcpy(buf, (void *) ip + offset, len - offset);
    if (0 == handle_udp((struct udphdr *) buf, len - offset))
	return 0;
    clt = AgentAddr_lookup_or_add(&Sources, ip->ip_src);
    clt->count++;
    srv = AgentAddr_lookup_or_add(&Destinations, ip->ip_dst);
    srv->count++;
    return 1;
}

int
handle_ether(const u_char * pkt, int len)
{
    char buf[PCAP_SNAPLEN];
    struct ether_header *e = (void *) pkt;
    if (ETHERTYPE_IP != ntohs(e->ether_type))
	return 0;
    memcpy(buf, pkt + ETHER_HDR_LEN, len - ETHER_HDR_LEN);
    return handle_ip((struct ip *) buf, len - ETHER_HDR_LEN);
}

void
handle_pcap(u_char * udata, const struct pcap_pkthdr *hdr, const u_char * pkt)
{
    if (hdr->caplen < ETHER_HDR_LEN)
	return;
    if (0 == handle_ether(pkt, hdr->caplen))
	return;
    query_count_intvl++;
    query_count_total++;
    last_ts = hdr->ts;
}

void
cron_pre(void)
{
    AgentAddr_sort(&Sources);
    AgentAddr_sort(&Destinations);
    StringCounter_sort(&Tlds);
    StringCounter_sort(&Slds);
}

void
cron_post(void)
{
    query_count_intvl = 0;
}

void
keyboard(void)
{
    int ch;
    /*move(w->_maxy-1, 0); */
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
    case 't':
	SubReport = Qtypes_report;
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
    default:
	break;
    }
}

void
Help_report(void)
{
    printw(" S - Sources list\n");
    printw(" D - Destinations list\n");
    printw(" T - Query types\n");
    printw(" 1 - TLD list\n");
    printw(" 2 - SLD list\n");
    printw("^R - Reset counters\n");
    printw("^X - Exit\n");
    printw("\n");
    printw("? - this\n");
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
    case 38:
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

void
StringCounter_report(StringCounter * list, char *what)
{
    StringCounter *sc;
    int nlines = w->_maxy - 6;
    printw("%-20s %9s %6s\n", what, "count", "%");
    printw("%-20s %9s %6s\n",
	"--------------------", "---------", "------");
    for (sc = list; sc; sc = sc->next) {
	printw("%-20.20s %9d %6.1f\n",
	    sc->s,
	    sc->count,
	    100.0 * sc->count / query_count_total);
	if (0 == --nlines)
	    break;
    }
}

void
StringCounter_free(StringCounter **headP)
{
    StringCounter *sc;
    void *next;
    for(sc=*headP; sc; sc=next) {
	next = sc->next;
	free(sc->s);
	free(sc);
    }
    *headP = NULL;
}

void
Tld_report(void)
{
    StringCounter_report(Tlds, "TLD");
}

void
Sld_report(void)
{
    StringCounter_report(Slds, "SLD");
}

void
Qtypes_report(void)
{
    int type;
    int nlines = w->_maxy - 6;
    printw("%-10s %9s %6s\n", "Query Type", "count", "%");
    printw("%-10s %9s %6s\n", "----------", "---------", "------");
    for (type = 0; type < T_MAX; type++) {
	if (0 == qtype_counts[type])
	    continue;
	printw("%-10s %9d %6.1f\n",
	    qtype_str(type),
	    qtype_counts[type],
	    100.0 * qtype_counts[type] / query_count_total);
	if (0 == --nlines)
	    break;
    }
}

void
AgentAddr_report(AgentAddr * list, const char *what)
{
    AgentAddr *agent;
    int nlines = w->_maxy - 6;
    printw("%-16s %9s %6s\n", what, "count", "%");
    printw("%-16s %9s %6s\n", "----------------", "---------", "------");
    for (agent = list; agent; agent = agent->next) {
	printw("%-16s %9d %6.1f\n",
	    anon_inet_ntoa(agent->src),
	    agent->count,
	    100.0 * agent->count / query_count_total);
	if (0 == --nlines)
	    break;
    }
}

void
AgentAddr_free(AgentAddr **headP)
{
    AgentAddr *aa;
    void *next;
    for(aa=*headP; aa; aa=next) {
	next = aa->next;
	free(aa);
    }
    *headP = NULL;
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
    move(0, 0);
    printw("%d new queries, %d total queries",
	query_count_intvl, query_count_total);
    clrtoeol();
    if (last_ts.tv_sec) {
	move(0, 50);
	printw("%s", ctime(&last_ts.tv_sec));
    }
    move(2, 0);
    clrtobot();
    if (SubReport)
	SubReport();
    refresh();
}

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
    query_count_intvl = 0;
    query_count_total = 0;
    memset(qtype_counts, '\0', sizeof(qtype_counts));
    memset(qclass_counts, '\0', sizeof(qclass_counts));
    AgentAddr_free(&Sources);
    AgentAddr_free(&Destinations);
    StringCounter_free(&Tlds);
    StringCounter_free(&Slds);
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
    fprintf(stderr, "\t-s\tEnable 2nd level domain stats collection\n");
    exit(1);
}

int
main(int argc, char *argv[])
{
    char errbuf[PCAP_ERRBUF_SIZE];
    int x;
    struct stat sb;
    int readfile_state = 0;
    struct bpf_program fp;

    port53 = htons(53);
    SubReport = Sources_report;
    ignore_addr.s_addr = 0;
    progname = strdup(strrchr(argv[0], '/') ? strchr(argv[0], '/') + 1 : argv[0]);
    srandom(time(NULL));
    ResetCounters();

    while ((x = getopt(argc, argv, "ab:i:ps")) != -1) {
	switch (x) {
	case 'a':
	    anon_flag = 1;
	    break;
	case 's':
	    sld_flag = 1;
	    break;
	case 'p':
	    promisc_flag = 0;
	    break;
	case 'b':
	    bpf_program_str = strdup(optarg);
	    break;
	case 'i':
	    ignore_addr.s_addr = inet_addr(argv[2]);
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
    init_curses();
    while (0 == Quit) {
	if (readfile_state < 2)
	    x = pcap_dispatch(pcap, 100, handle_pcap, NULL);
	if (0 == x && 1 == readfile_state) {
	    /* block on keyboard until user quits */
	    readfile_state++;
	    nodelay(w, 0);
	}
	keyboard();
	cron_pre();
	report();
	cron_post();
    }

    pcap_close(pcap);
    return 0;
}
