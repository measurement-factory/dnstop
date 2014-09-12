#!/bin/sh
set -e
wget -O /tmp/tlds http://data.iana.org/TLD/tlds-alpha-by-domain.txt
exec </tmp/tlds

cat <<EOF

static const char *KnownTLDS[] = {
	".",	/* special case for root zone */
EOF

while read t ; do
	echo $t | grep -sq '^#' && continue;
	x=`echo $t | tr A-Z a-z`
	echo "	\"$x\","
	if test $x = "arpa" ; then
		echo "	\"in-addr.arpa\",	 /* because dnstop treats in-addr.arpa as a TLD */"
	fi
done

cat <<EOF
	NULL
};
EOF
