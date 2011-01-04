
#ifndef INX_ADDR_H
#define INX_ADDR_H

typedef union {
#if USE_IPV6
	struct in6_addr in6;
#endif
	struct {
#if USE_IPV6
		struct in_addr pad0;
		struct in_addr pad1;
		struct in_addr pad2;
#endif
		struct in_addr in4;
	} _;
} inX_addr;

extern int inXaddr_version(const inX_addr *);
extern const char * inXaddr_ntop(const inX_addr *, char *, socklen_t len);
extern int inXaddr_pton(const char *, inX_addr *);
extern unsigned int inXaddr_hash(const inX_addr *, unsigned int bits);
extern int inXaddr_cmp(const inX_addr *a, const inX_addr *b);
extern inX_addr inXaddr_mask (const inX_addr *a, const inX_addr *mask);

extern int inXaddr_assign_v4(inX_addr *, const struct in_addr *);
extern int inXaddr_assign_v6(inX_addr *, const struct in6_addr *);

#endif /* INX_ADDR_H */
