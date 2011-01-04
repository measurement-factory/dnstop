PROG=dnstop
DATE != date +%Y%m%d

OPTFLAGS= -DUSE_IPV6=1
CC=gcc
CFLAGS=-g -Wall -O2 ${OPTFLAGS} # -pg
LIBS=-lpcap -lcurses 

prefix=/usr/local
exec_prefix=${prefix}
bindir=${exec_prefix}/bin
datarootdir=${prefix}/share
datadir=${datarootdir}
mandir=${datarootdir}/man

SRCS=	$(PROG).c \
	hashtbl.c hashtbl.h \
	known_tlds.h \
	lookup3.c \
	inX_addr.c inX_addr.h

OBJS=	$(PROG).o \
	hashtbl.o \
	lookup3.o \
	inX_addr.o

all: $(PROG)

$(PROG): $(OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(OBJS) ${LIBS}

dnstop.o: dnstop.c
	$(CC) $(CFLAGS) -c $<

clean:
	rm -f $(PROG) $(OBJS) $(PROG).core $(PROG).c~

distclean: clean
	rm -rf autom4te.cache
	rm -f config.h
	rm -f config.log
	rm -f config.status
	rm -f config.status.lineno
	rm -f Makefile

tar:
	mkdir $(PROG)-$(DATE)
	cp -p LICENSE CHANGES $(SRCS) $(PROG).8 $(PROG)-$(DATE)
	cp -p configure Makefile.in config.h.in install-sh $(PROG)-$(DATE)
	perl -pi -e "s/\@VERSION\@/$(DATE)/" $(PROG)-$(DATE)/dnstop.c
	tar czvf $(PROG)-$(DATE).tar.gz $(PROG)-$(DATE)
	chmod 444 $(PROG)-$(DATE).tar.gz
	rm -rf $(PROG)-$(DATE)
	md5 *.gz > MD5s.txt

install: $(PROG)
	install -m 755 $(PROG) ${bindir}
	install -m 644 $(PROG).8 ${mandir}/man8

uninstall:
	rm -f ${bindir}/$(PROG)
	rm -f ${mandir}/man8/$(PROG).8
