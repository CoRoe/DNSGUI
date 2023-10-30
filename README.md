# GUI Configuration of DNS Resolution #

## Overview

This project is a simple GUI interface to the parameters of the DNS resolver
that is part of systemd. It is handy for instance when having to go through a
captive portal that the secure DNS queries.

It contains two components:

  * A GUI written in PyQt5 (*/usr/local/bin/dnsconf.py*); it is
    essentially an editor for the configuration file
    */etc/systemd/resolved.conf*.

  * an applet for the Cinnamon desktop that starts the GUI component
    (*/usr/share/cinnamon/applets/dnssettings@conrad.roeber*).

![Screenshot](screenshot.png)

For security reasons, the bash script has to be placed in a directory to which
the user does not have write access. Otherwise malicious software running in
the context of the user could modify the script and perform arbitrary actions
with root privileges.

The applet runs on the Cinnamon desktop and interacts with the systemd DNS
resolver.

## Installation

Call *install.sh*; the shell script copies the Java Scipt and JSON files in
applet/files/${APPLET} to /usr/share/cinnamon/applets/${APPLET}, where
${APPLET} is *dnssetting@conrad.roeber*, the applet's UUID.

## Debugging

Press Alt-F2 to enter the Cinnamon debugger; in the prompt type 'lg'.

## Limitations

  * The file */etc/systemd/resolved.conf* must already exist.

  * The application handles only /etc/systemd/resolved.conf but not the other
    possible locations like /run/systemd or /usr/lib/systemd, nor does it
    handle snippets.

  * The application queries the user's password only once. If it is wrong and
    sudo fails, quit the program and start over.

## Files

/etc/systemd/resolved.conf

## See also

resolved.conf(5)
