#!/bin/sh

APPLET=dnssettings@conrad.roeber

# Install the Python and helper scripts in /usr/local/bin
cp src/dns-conf.py src/dns-conf.helper.sh /usr/local/bin

# Install the applet for the current user
mkdir -p /usr/share/cinnamon/applets/${APPLET}
cp applet/files/${APPLET}/*.js   /usr/share/cinnamon/applets/${APPLET}
cp applet/files/${APPLET}/*.json /usr/share/cinnamon/applets/${APPLET}
