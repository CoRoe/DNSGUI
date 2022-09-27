#!/bin/sh

APPLET=dnssettings@conrad.roeber

# Install the Python and helper scripts in ~/.local/bin
cp src/dns-conf.py src/dns-conf.helper.sh ~/.local/share/cinnamon/applets/${APPLET}

# Install the applet for the current user
mkdir -p ~/.local/share/cinnamon/applets/${APPLET}
cp applet/files/${APPLET}/*.js ~/.local/share/cinnamon/applets/${APPLET}
cp applet/files/${APPLET}/*.json ~/.local/share/cinnamon/applets/${APPLET}
