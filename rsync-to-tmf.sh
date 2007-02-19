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
"

chmod a+r $FILES

rsync -av $FILES measurement-factory.com:/httpd/htdocs/dns.measurement-factory.com/tools/dnstop/src
