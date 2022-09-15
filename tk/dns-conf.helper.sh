#!/bin/sh

# The script has exactly two arguments:
#
# - The tmp file with the new configuration (typically somewhere in /tmp)
# - The conf file (normally /etc/systemd/resolved.conf
#

# Must have two arguments
if [ "$#" -ne 2 ]; then
    echo "Usage: $0 TMPFILE CONFFILE" >&2
    exit 1
fi

if ! [ -e "$1" ]; then
    echo "$1 not found" >&2
    exit 1
fi

if ! [ -e "$2" ]; then
    echo "$2 not found" >&2
    exit 1
fi

if ! mv "$2" "$1.bak"; then
    echo "Cannot rename $2" >&2
    exit 1
fi

if ! cp "$1" "$2"; then
    echo "Cannot copy $1 to $2" >&2
    exit 1
fi

if ! /usr/bin/systemctl restart systemd-resolved.service; then
    echo "Cannot restart systemd-resolved.service" >&2
    exit 1
fi
