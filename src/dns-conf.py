#!/usr/bin/python3

import tkinter as tk
from tkinter import ttk, simpledialog, messagebox
import re
import os
import subprocess
import argparse


#
# https://web.archive.org/web/20201112011230/http://effbot.org/tkinterbook/grid.htm
# https://www.pythontutorial.net/tkinter/tkinter-optionmenu/
# https://www.tutorialspoint.com/python/tk_entry.htm
#
# Password entry: https://stackoverflow.com/questions/15724658/simplest-method-of-asking-user-for-password-using-graphical-dialog-in-python
#
# Sudo: https://www.python-forum.de/viewtopic.php?t=1393
#
# TODO Allow white space around the '=' signs in the configuration file.
#
# TODO Assign default values to all variables so that they have sensible
# values even when not present in resolved.conf.
#


class DNSselector(tk.Tk):
    """
    Displays a combobox and an entry field side-by-side.

    The combobox allows for selecting a DNS provider (such as Google or Quad9)
    or manually entering an IPv4 address in dotted notation.
    """
    def __init__(self, parent, row, text, values, **paddings):
        super(DNSselector, self).__init__()

        self.__parent = parent
        self.__values = values
        self.__ipaddr0 = values[0][1]

        # Creates a label with the explanatory text, an option menu (to select
        # the DNS provider), and an entry field (chosen IP address)
        label = ttk.Label(parent, text=text)
        label.grid(row=row, column=0, sticky='W', **paddings)

        self.__servers_combo = ttk.Combobox(parent)
        self.__servers_combo['values'] = [q[0] for q in values]
        self.__servers_combo['state'] = 'readonly'
        self.__servers_combo.bind('<<ComboboxSelected>>', self.on_server_changed)
        self.__servers_combo.grid(row=row, column=1, sticky='W',
                            **paddings)

        self.__ipaddr_txt = tk.StringVar()
        self.__ipaddr_entry = tk.Entry(parent, textvariable=self.__ipaddr_txt)
        self.__ipaddr_entry.grid(row=row, column=2)

        self.__ipaddr_entry.bind('<Key-Return> ', self.on_ip_changed)
        self.__ipaddr_entry.bind('<FocusOut> ', self.on_ip_changed)


    def get(self):
        #return self.__ipaddr_txt.get()
        return self.__ipaddr_entry.get()

    def set(self, value):
        self.__ipaddr0 = value
        print("Set '{}'".format(value))
        self.__ipaddr_txt.set(value)
        provider = self.__provider_from_ip(value)
        print(provider)
        self.__servers_combo.set(provider)

    # Given an IP address return the provider name
    def __provider_from_ip(self, ip):
        for pair in self.__values:
            if pair[1] == ip:
                return pair[0]
        return ''

    # Given a provide name return the IP address
    def __ip_from_provider(self, prov):
        for pair in self.__values:
            if pair[0] == prov:
                return pair[1]
        return ''

    # Invoked when the user selects a new server. The method updates the IP
    # address accordingly.
    def on_server_changed(self, event):
        #print('On server changed', event)
        server = self.__servers_combo.get()
        #print("New value:", server)
        i = [q[0] for q in self.__values].index(server)
        ipaddr = self.__ip_from_provider(server)
        self.__ipaddr_txt.set(ipaddr)
        self.__parent.on_value_changed()


    # Invoked when the IP address might have changed. The method updates the
    # server name according ly.
    def on_ip_changed(self, event):
        ip = self.__ipaddr_txt.get()
        print("on_ip_changed:", event, ip)
        provider = self.__provider_from_ip(ip)
        print(provider)
        #self.__servers_var.set(provider)
        self.__servers_combo.set(provider)
        self.__parent.on_value_changed()


    # Called after the value has been successfully saved. The instance is
    # flagged as 'not modified'.
    def config_written(self):
        self.__ipaddr0 = self.__ipaddr_txt.get()


    # Checks if a widget's value has been modified and needs to be saved.
    def is_modified(self):
        print("DNSselector.is_modified: v0={}, v={}".format( self.__ipaddr0,
                                                             self.__ipaddr_txt.get()))
        return self.__ipaddr0 != self.__ipaddr_txt.get()


class EnumSelector(tk.Tk):
    def __init__(self, parent, row, text, values, **paddings):
        super(EnumSelector, self).__init__()

        self.__parent = parent

        # The initial value. Its purpose is to track if the actual value of
        # the setting is has been modified and needs to be saved.
        #
        # - Initialised to the 1st element of the 'values' parameter of the
        #   constructor.
        #
        # - Updated to the current value when the configuration file is saved.
        self.__value0 = values[0]

        self.__label = ttk.Label(parent, text=text)
        self.__label.grid(row=row, column=0, sticky='W',
                          ** paddings)

        self.__value_combo = ttk.Combobox(parent)

        # Initialise with the 1st value of the list of valid values:
        self.__value_combo.set(values[0])
        self.__value_combo.grid(row=row, column=1, sticky='W',
                                **paddings)
        self.__value_combo['values'] = values
        self.__value_combo['state'] = 'readonly'

        self.__value_combo.bind('<<ComboboxSelected>> ',
                                self.__on_value_changed)

    def get(self):
        return self.__value_combo.get()

    def set(self, v):
        self.__value_combo.set(v)
        self.__value0 = v
        print("EnumSelector.set: ", self.__value0, self.__value_combo.get())

    # Called after the value has been successfully saved. The instance is
    # flagged as 'not modified'.
    def config_written(self):
        self.__value0 = self.__value_combo.get()

    # Checks i the value has been modified.
    def is_modified(self):
        print("EnumSelector.is_modified:",
              self.__value0, self.__value_combo.get())
        return self.__value0 != self.__value_combo.get()

    def __on_value_changed(self, event):
        print("EnumSelector.on_value_changed:")
        self.__parent.on_value_changed()


class RootWindow(tk.Tk):
    #
    # Reihenfolge:
    #
    # - Widgets erzeugen; zuerst leer, weil die Werte noch nicht bekannt sind
    #
    # - conf-File lesen und Werte den Widgets zuweisen. Um Änderungen
    #   festellen zu können, sowohl den initialen Wert (Methode set()) und den
    #   momentanen Wert (steht im Widget) merken.
    #
    # - is_modified() vergleicht den momentanen und den initialen Wert.

    DNSproviders = [['Quad9',      '9.9.9.9'],
                    ['Google',     '8.8.8.8'],
                    ['Cloudflare', '1.1.1.1'],
                    ['Other',      '']]
    __paddings = {'padx': 10, 'pady': 10}
    __tmp_fn = '/tmp/resolved.conf'

    #
    # Class constructor
    #
    def __init__(self, config_fn, run_as_root, script_path):
        super(RootWindow, self).__init__()

        self.__run_as_root = run_as_root
        self.__script_path = script_path
        self.__helper_path = self.__script_path.replace(".py", ".helper.sh")
        self.__config_fn = config_fn
        self.__password = None

        self.__handlers = {}
        self.__create_widgets()
        self.__read_config(self.__config_fn)
        #self.write_config()


    #
    # Read the DNS configuration from /etc/systemd/resolved.conf
    #
    def __read_config(self, conf_fn):
        print("Reading configuration ...")
        try:
            with open(conf_fn, 'r') as ifile:
                for line in ifile:
                    print('>', line[:-1])
                    # Extract key and value.
                    try:
                        m = re.match('^([A-Za-z]+)=([a-z0-9.-]+)', line[:-1])
                        if m:
                            key = m.group(1)
                            value = m.group(2)
                            print('key:', key, ', value:', value)
                            # If a widget is defined for the particular key
                            # then call the set() method of the widget.
                            if key in self.__handlers:
                                self.__handlers[key].set(value)
                    except re.error as e:
                        print("RE problem", e)
        except IOErr as e:
            print("Cannot open", conf_fn, e)


    #
    # Save the modified configuration
    #
    def __write_config(self, conf_fn, tmp_fn):
        try:
            with open(conf_fn, 'r') as f_in:
                with open(tmp_fn, 'w') as f_out:
                    updated_vars = set()
                    for line in f_in:
                        m = re.match('^([A-Za-z]+)=', line)
                        if m:
                            var = m.group(1)
                            if var in self.__handlers:
                                f_out.write(
                                      "{}={}\n".format(var, self.__handlers[var].get()))
                                updated_vars.add(var)
                            else:
                                f_out.write(line)
                        else:
                            f_out.write(line)
                    # resolved.conf might not define all
                    for var in self.__handlers:
                        if not var in updated_vars:
                            print("Missing:", var)
                            f_out.write(
                                      "{}={}\n".format(var,
                                                       self.__handlers[var].get()))
        except IOErr as e:
            print("Cannot open", e)


    # Tests whether any value has been modified
    def __any_value_modified(self):
        for i in self.__handlers:
            if self.__handlers[i].is_modified():
               return True
        return False


    # Called by widgets when their values change
    def on_value_changed(self):
        m = self.__any_value_modified()
        print("Value of some widget has changed!", m)
        if m:
            self.__b_apply['state'] = tk.NORMAL
            self.__b_apply.focus_set()
        else:
            self.__b_apply['state'] = tk.DISABLED
            self.__b_close.focus_set()


    # Called by widgets when the 'apply' __b_close is pressed
    def __on_apply(self):
        """
        'apply' button pressed.
        """
        print("on_apply")
        if self.__any_value_modified():
            print("... something changed")
            if self.__run_as_root:
                # If the password has been previously set don't ask again
                if not self.__password:
                    self.__password = simpledialog.askstring("Password needed",
                                                             "Password:",
                                                             parent=self,
                                                             show='*')
                    #print("Password =", self.__password)
                # If the user has actually entered a password then proceed.
                if self.__password:
                    # Write modified values to a temp file and ...
                    self.__write_config(self.__config_fn, RootWindow.__tmp_fn)
                    # ... copy the temp file to /etc and restart the daemon
                    self.__run_helper_script(True)
                    for i in self.__handlers:
                        self.__handlers[i].config_written()
                    self.__b_apply['state'] = tk.DISABLED
                    self.__b_close.focus_set()
            else:
                # Run as normal user
                # Write modified values to a temp file and ...
                self.__write_config(self.__config_fn, RootWindow.__tmp_fn)
                # ... copy the temp file to /etc and restart the daemon
                self.__run_helper_script(False)
                for i in self.__handlers:
                    self.__handlers[i].config_written()
                self.__b_apply['state'] = tk.DISABLED
        else:
            print("... nothing changed")


    def __on_close(self):
        """
        Close button pressed
        """
        if self.__any_value_modified():
            answer = tk.messagebox.askyesno('Exit Application',
                                            'Discard changes?',
                                            icon = 'question')
            if answer == True:
                print("Discarding changes")
                self.quit()
        else:
            self.quit()


    def __on_return_event(self, event):
        print('on_return')
        if event.widget == self.__b_apply:
            print("apply")
            self.__on_apply()
        elif event.widget == self.__b_close:
            print("close")
            self.__on_close()

    #
    # Create the widgets and initialise them with the values read from the
    # conf file.
    #
    def __create_widgets(self):
        self.title("DNS Configuration")
        #self.minsize(500,400)
        #p = [q[0] for q in RootWindow.DNSproviders]
        #print(p)

        row = 0
        h = DNSselector(self, row=row, text='DNS server',
                        values=RootWindow.DNSproviders,
                        **RootWindow.__paddings)
        self.__handlers['DNS'] = h

        row = row + 1
        h = DNSselector(self, row=row, text='Fallback DNS server',
                        values=RootWindow.DNSproviders,
                        **RootWindow.__paddings)
        self.__handlers['FallbackDNS'] = h

        row = row + 1
        h = EnumSelector(self, row=row, text='DNS over TLS',
                         values=['no', 'yes', 'opportunistic'],
                         **RootWindow.__paddings)
        self.__handlers['DNSOverTLS'] = h

        row = row + 1
        h = EnumSelector(self, row=row, text='DNSSEC',
                         values=['no', 'yes', 'allow-downgrade'],
                         **RootWindow.__paddings)
        self.__handlers['DNSSEC'] = h

        row = row + 1
        self.__b_apply = tk.Button(text="Apply", command=self.__on_apply)
        self.__b_apply['state'] = tk.DISABLED
        self.__b_apply.grid(row=row, column=2, sticky=tk.E,
                            **RootWindow.__paddings)

        self.__b_close = tk.Button(text="Close", command=self.__on_close)
        self.__b_close.grid(row=row, column=3, sticky=tk.W,
                            **RootWindow.__paddings)
        self.__b_close.focus_set()

        self.bind('<Return>', self.__on_return_event)


    def __run_helper_script(self, use_sudo):
        # https://docs.python.org/3/library/subprocess.html
        if use_sudo:
            p = subprocess.Popen(('sudo', '-S', self.__helper_path,
                                  RootWindow.__tmp_fn, self.__config_fn),
                                 stdin=subprocess.PIPE,
                                 stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE)
            output = p.communicate(self.__password.encode())
        else:
            p = subprocess.Popen((self.__helper_path,
                                  RootWindow.__tmp_fn, self.__config_fn),
                                 stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE)
            output = p.communicate()

        # Subprocess has terminatred.
        if p.returncode != 0:
            print("Return code: ", p.returncode)
            print("Subprocess output:", output[0].decode())
            print("Subprocess output:", output[1].decode())
            message = output[0].decode()
            if message != '':
                message += '\n'
            message += output[1].decode()
            messagebox.showerror("Error", message)
            return False
        else:
            return True


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Display and modify settings '
                                     'of the systemd DNS resolver.')
    parser.add_argument('--config',
                        default='/etc/systemd/resolved.conf',
                        help='path of the conf file; defaults '
                        'to /etc/systemd/resolved.conf')
    parser.add_argument('--no-root',
                        action='store_true',
                        help='do not run as root; default is to run as root')
    args = parser.parse_args()

    root_window = RootWindow(config_fn=args.config,
                             run_as_root=not args.no_root,
                             script_path=os.path.abspath( __file__ ))
    root_window.mainloop()
