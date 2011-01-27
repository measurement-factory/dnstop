#!/bin/sh

FILES="
CHANGES
LICENSE
Makefile
dnstop.8
dnstop.c
known_tlds.h
hashtbl.c
hashtbl.h
lookup3.c
inX_addr.c
inX_addr.h
"

chmod a+r $FILES

rsync -av $FILES measurement-factory.com:/httpd/htdocs/dns.measurement-factory.com/tools/dnstop/src
