#!/bin/sh
set -e
wget -O /tmp/newgtlds https://newgtlds.icann.org/newgtlds.csv
exec </tmp/newgtlds

cat <<EOF

static const char *NewGTLDs_array[] = {
EOF
IFS=','

while read t x ; do
	echo $t | grep -sq '^#' && continue;
	echo $t | grep -sq '^>>>' && continue;
	x=`echo $t | tr A-Z a-z`
	test "$t" = "tld" && continue;
	echo "	\"$x\","
done

cat <<EOF
	NULL
};
EOF
