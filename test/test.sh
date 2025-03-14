#!/bin/sh

# Helper script
# Verifies that resolved.conf is modified as intended

TMPFILE=/tmp/resolved.conf

cp resolved.conf ${TMPFILE}
../src/dnsconf.py --config resolved.conf
diff resolved.conf ${TMPFILE}
rm ${TMPFILE}
