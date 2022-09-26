#!/bin/sh

# The script has exactly two arguments:
#
# - The tmp file with the new configuration (typically somewhere in /tmp)
#
# - The conf file (normally /etc/systemd/resolved.conf
#

# Must have two arguments
if [ "$#" -ne 2 ]; then
    echo "Usage: $0 TMPFILE CONFFILE" >&2
    exit 1
fi

TMP=$1
CONF=$2

if ! [ -e "${TMP}" ]; then
    echo "${TMP} not found" >&2
    exit 1
fi

if ! [ -e "${CONF}" ]; then
    echo "${CONF} not found" >&2
    exit 1
fi

if ! mv -f "${CONF}" "${CONF}.bak"; then
    echo "Cannot rename ${CONF}" >&2
    exit 1
fi

if ! cp "${TMP}" "${CONF}"; then
    echo "Cannot copy ${TMP} to ${CONF}" >&2
    exit 1
fi

if ! /usr/bin/systemctl restart systemd-resolved.service; then
    echo "Cannot restart systemd-resolved.service" >&2
    exit 1
fi
