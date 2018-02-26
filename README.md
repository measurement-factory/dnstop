# DNSTOP: STAY ON TOP OF YOUR DNS TRAFFIC

_dnstop_ is a libpcap application (like tcpdump) that displays various
tables of DNS traffic on your network. Currently _dnstop_ displays
tables of:

- Source IP addresses
- Destination IP addresses
- Query types
- Response codes
- Opcodes
- Top level domains
- Second level domains
- Third level domains
- etc...

_dnstop_ supports both IPv4 and IPv6 addresses.

To help find especially undesirable DNS queries, _dnstop_ provides a number of filters. The filters tell _dnstop_ to display only the following types of queries:

- For unknown/invalid TLDs
- A queries where the query name is already an IP address
- PTR queries for RFC1918 address space
- Responses with code REFUSED 

_dnstop_ can either read packets from the live capture device, or from a tcpdump savefile.

See also http://dns.measurement-factory.com/tools/dnstop/.

