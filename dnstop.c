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

typedef struct _AgentAddr AgentAddr;
struct _AgentAddr {
	struct in_addr src;
	int qcount;
	AgentAddr *next;
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

char *device = NULL;
struct in_addr ignore_addr;
pcap_t *pcap = NULL;
struct bpf_program fp;
WINDOW *w = NULL;
static unsigned short port53;
void (*SubReport)(void) = NULL;
int Quit = 0;

int query_count_intvl = 0;
int query_count_total = 0;
int qtype_counts[ns_t_max];
int qclass_counts[ns_c_max];
AgentAddr *Sources = NULL;
AgentAddr *Destinations = NULL;
struct timeval last_ts;

void Sources_report(void);
void Destinations_report(void);
void Qtypes_report(void);
void Help_report(void);

AgentAddr *
AgentAddr_lookup_or_add(AgentAddr **headP, struct in_addr a)
{
	AgentAddr **T;
	for(T  = headP; (*T); T=&(*T)->next)
		if ((*T)->src.s_addr == a.s_addr)
			return (*T);
	(*T) = calloc(1, sizeof(**T));
	(*T)->src = a;
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
	return 0;
}

void
AgentAddr_sort(AgentAddr **headP)
{
	foo *sortme;
	int n_agents = 0;
	int i;
	AgentAddr *a;
	for (a=*headP; a; a=a->next)
		n_agents++;
	sortme = calloc(n_agents, sizeof(foo));
	n_agents = 0;
	for (a=*headP; a; a=a->next) {
		sortme[n_agents].cnt = a->qcount;
		sortme[n_agents].ptr = a;
		n_agents++;
	}
	qsort(sortme, n_agents, sizeof(foo), foo_cmp);
	for (i=0; i<n_agents; i++) {
		*headP = sortme[i].ptr;
		headP = &(*headP)->next;
	}
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
            if ((*off) + len > sz)      /* message is too short */
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

        if (len < sizeof(qh))
                return 0;

        memcpy(&us, buf+00, 2);
        qh.id = ntohs(us);

        memcpy(&us, buf+2, 2);
        qh.qr = (us >> 15) & 0x01;
        qh.opcode = (us >> 11) & 0x0F;
        qh.aa = (us >> 10) & 0x01;
        qh.tc = (us >> 9) & 0x01;
        qh.rd = (us >> 8) & 0x01;
        qh.ra = (us >> 7) & 0x01;
        qh.rcode = us & 0x0F;

        memcpy(&us, buf+4, 2);
        qh.qdcount = ntohs(us);

        memcpy(&us, buf+6, 2);
        qh.ancount = ntohs(us);

        memcpy(&us, buf+8, 2);
        qh.nscount = ntohs(us);

        memcpy(&us, buf+10, 2);
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

        memcpy(&us, buf+offset, 2);
        qtype = ntohs(us);
        memcpy(&us, buf+offset+2, 2);
        qclass = ntohs(us);

	qtype_counts[qtype]++;
	qclass_counts[qclass]++;

	return 1;
}

int
handle_udp(const struct udphdr *udp, int len)
{
	char buf[PCAP_SNAPLEN];
	if (port53 != udp->uh_dport)
		return 0;
	memcpy(buf, udp+1, len-sizeof(*udp));
	handle_dns(buf, len-sizeof(*udp));
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
	clt = AgentAddr_lookup_or_add(&Sources, ip->ip_src);
	clt->qcount++;
	srv = AgentAddr_lookup_or_add(&Destinations, ip->ip_dst);
	srv->qcount++;
	if (IPPROTO_UDP != ip->ip_p)
		return 0;
	memcpy(buf, (void*)ip+offset, len-offset);
	return handle_udp((struct udphdr*) buf, len-offset);
}

int
handle_ether(const u_char *pkt, int len)
{
	char buf[PCAP_SNAPLEN];
	struct ether_header *e = (void*) pkt;
	if (ETHERTYPE_IP != ntohs(e->ether_type))
		return 0;
	memcpy(buf, pkt+ETHER_HDR_LEN, len-ETHER_HDR_LEN);
	return handle_ip((struct ip*) buf, len-ETHER_HDR_LEN);
}

void
handle_pcap(u_char *udata, const struct pcap_pkthdr *hdr, const u_char *pkt)
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
cron(void)
{
	query_count_intvl = 0;
	AgentAddr_sort(&Sources);
	AgentAddr_sort(&Destinations);
}

void
keyboard(void)
{
	int ch;
	move(w->_maxy-1, 0);
	ch = getch() & 0xff;
	if (ch >= 'A' && ch <= 'Z')
		ch += 'a' - 'A';
	switch(ch) {
	case 's':
		SubReport = Sources_report;
		break;
	case 'd':
		SubReport = Destinations_report;
		break;
	case 't':
		SubReport = Qtypes_report;
		break;
	case 'q':
		Quit = 1;
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
	printw("s - Sources list\n");
	printw("d - Destinations list\n");
	printw("t - Query types\n");
	printw("q - Quit\n");
	printw("\n");
	printw("? - this\n");
}

char *
qtype_str(int t)
{
	static char buf[30];
	switch(t) {
	case ns_t_a:
		return "A?";
		break;
	case ns_t_ns:
		return "NS?";
		break;
	case ns_t_cname:
		return "CNAME?";
		break;
	case ns_t_soa:
		return "SOA?";
		break;
	case ns_t_ptr:
		return "PTR?";
		break;
	case ns_t_mx:
		return "MX?";
		break;
	case ns_t_txt:
		return "TXT?";
		break;
	case ns_t_sig:
		return "SIG?";
		break;
	case ns_t_key:
		return "KEY?";
		break;
	case ns_t_aaaa:
		return "AAAA?";
		break;
	case ns_t_loc:
		return "LOC?";
		break;
	case ns_t_srv:
		return "SRV?";
		break;
	case 38:
		return "A6?";
		break;
	case ns_t_any:
		return "ANY?";
		break;
	default:
		snprintf(buf, 30, "#%d?", t);
		return buf;
	}
	/* NOTREACHED */
}

void
Qtypes_report(void)
{
	int type;
	int nlines = w->_maxy - 6;
	printw("%-10s %9s %6s\n", "Query Type", "count", "%");
	printw("%-10s %9s %6s\n", "----------", "---------", "------");
	for(type = 0; type<ns_t_max; type++) {
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
AgentAddr_report(AgentAddr *list, const char *what)
{
	AgentAddr *agent;
	int nlines = w->_maxy - 6;
	printw("%-16s %9s %6s\n", what, "count", "%");
	printw("%-16s %9s %6s\n", "----------------", "---------", "------");
	for(agent = list; agent; agent=agent->next) {
		printw("%-16s %9d %6.1f\n",
			inet_ntoa(agent->src),
			agent->qcount,
			100.0 * agent->qcount / query_count_total);
		if (0 == --nlines)
			break;
	}
}

void
Sources_report(void)
{
	AgentAddr_report(Sources, "Sources");
}

void
Destinations_report(void)
{
	AgentAddr_report(Destinations, "Destinations");
}

void report(void)
{
	move(0,0);
	printw("%d new queries, %d total queries",
		query_count_intvl, query_count_total);
	move(0,40);
	printw("%s", ctime(&last_ts.tv_sec));
	move(2,0);
	clrtobot();
	if (SubReport)
		SubReport();
	refresh();
}

void init_curses(void)
{
	w = initscr();
	cbreak();	
	noecho();
	nodelay(w, 1);
}

int
main(int argc, char *argv[])
{
	char errbuf[PCAP_ERRBUF_SIZE];
	int x;
	struct stat sb;
	int readfile_flag = 0;

	port53 = htons(53);
	SubReport = Sources_report;

	if (argc < 2) {
		fprintf(stderr, "usage: %s netdevice\n", argv[0]);
		exit(1);
	}
	device = strdup(argv[1]);

	if (argc > 2) {
		ignore_addr.s_addr = inet_addr(argv[2]);
	} else {
		ignore_addr.s_addr = inet_addr("0.0.0.0");
	}

	if (0 == stat(device, &sb))
		readfile_flag = 1;
	if (readfile_flag) {
		pcap = pcap_open_offline(device, errbuf);
	} else {
		pcap = pcap_open_live(device, PCAP_SNAPLEN, 1, 1000, errbuf);
	}
	if (NULL == pcap) {
		fprintf(stderr, "pcap_open_*: %s\n", errbuf);
		exit(1);
	}

	memset(&fp, '\0', sizeof(fp));
	x = pcap_compile(pcap, &fp, "udp dst port 53", 1, NULL);
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
		x = pcap_dispatch(pcap, 100, handle_pcap, NULL);
		if (0 == x && readfile_flag)
			break;
		report();
		cron();
		keyboard();
	}

	pcap_close(pcap);
	return 0;
}
