# GUI Configuration of DBS Resolution #

## Applet

### Installation

Call *install.sh*; the shell script copies the Java Scipt and JSON files in
applet/files/${APPLET} to ~/.local/share/cinnamon/applets/${APPLET}, where
${APPLET} is *dnssetting@conrad.roeber*, the applet's UUID.

### Debugging

Press Alt-F2 to enter the Cinnamon debugger; in the prompt type 'lg'.

## Python Script

This tool provides a GUI to edit some parameters of the DNS resolver that
comes with *systemd*.

### Limitations

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
