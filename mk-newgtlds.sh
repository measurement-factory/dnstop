#!/bin/sh
set -e
wget -O /tmp/newgtlds https://www.icann.org/resources/registries/gtlds/v1/newgtlds.csv
exec </tmp/newgtlds

cat <<EOF

static const char *NewGTLDs_array[] = {
EOF
IFS=','

while read t x ; do
	echo $t | grep -sq '^#' && continue;
	echo $t | grep -sq '^>>>' && continue;
	x=`echo $t | tr A-Z a-z | tr -d '"'`
	test "$x" = "tld" && continue;
	echo "	\"$x\","
done

cat <<EOF
	NULL
};
EOF
