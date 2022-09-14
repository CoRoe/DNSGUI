#!/usr/bin/python3

import tkinter as tk
from tkinter import ttk
import re
import argparse


#
# https://web.archive.org/web/20201112011230/http://effbot.org/tkinterbook/grid.htm
# https://www.pythontutorial.net/tkinter/tkinter-optionmenu/
# https://www.tutorialspoint.com/python/tk_entry.htm
#
# TODO Allow white space around the '=' signs in the configuration file.
#
# TODO Assign default values to all variables so that they have sensible
# values even when not present in resolved.conf.
#
# TODO Make sure that all variable/value pairs are written to resolved.conf.
#
# TODO Check if one or more variables have been modified after they have been
# read from the file.
#

class DNSselector(tk.Tk):
    def __init__(self, parent, row, text, values, **paddings):
        super(DNSselector, self).__init__()

        self.__parent = parent
        self.__values = values
        self.__ipaddr0 = values[0][1]

        # Creates a label with the explanatory text, an option menu (to select
        # the DNS provider), and an entry field (chosen IP address)
        print("create_widgets", text, row)
        self.__label = ttk.Label(parent, text=text)
        self.__label.grid(row=row, column=0, sticky='W',
                          **paddings)

        print([q[0] for q in values])

        self.__servers_var = tk.StringVar()
        self.__servers = ttk.Combobox(parent,
                                      textvariable=self.__servers_var)
        self.__servers['values'] = [q[0] for q in values]
        self.__servers['state'] = 'readonly'
        self.__servers.bind('<<ComboboxSelected>>', self.on_server_changed)
        self.__servers.grid(row=row, column=1, sticky='W',
                            **paddings)

        self.__ipaddr_var = tk.StringVar()
        self.__ipaddr = tk.Entry(parent, textvariable=self.__ipaddr_var)
        self.__ipaddr.grid(row=row, column=2)

        self.__ipaddr.bind('<Key-Return> ', self.on_ip_changed)
        self.__ipaddr.bind('<FocusOut> ', self.on_ip_changed)


    def get(self):
        return self.__ipaddr_var.get()

    def set(self, value):
        self.__ipaddr0 = value
        print("Set '{}'".format(value))
        self.__ipaddr_var.set(value)
        provider = self.__provider_from_ip(value)
        print(provider)
        self.__servers_var.set(provider)

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
        server = self.__servers_var.get()
        #print("New value:", server)
        i = [q[0] for q in self.__values].index(server)
        ipaddr = self.__ip_from_provider(server)
        self.__ipaddr_var.set(ipaddr)
        self.__parent.on_value_changed()


    # Invoked when the IP address might have changed. The method updates the
    # server name according ly.
    def on_ip_changed(self, event):
        ip = self.__ipaddr_var.get()
        print("on_ip_changed:", event, ip)
        provider = self.__provider_from_ip(ip)
        print(provider)
        self.__servers_var.set(provider)
        self.__parent.on_value_changed()


    # Called after the value has been successfully saved. The instance is
    # flagged as 'not modified'.
    def config_written(self):
        self.__ipaddr0 = self.__ipaddr_var.get()


    # Checks if a widget's value has been modified and needs to be saved.
    def is_modified(self):
        print("DNSselector.is_modified: v0={}, v={}".format( self.__ipaddr0,
                                                             self.__ipaddr_var.get()))
        return self.__ipaddr0 != self.__ipaddr_var.get()


class EnumSelector(tk.Tk):
    def __init__(self, parent, row, text, values, **paddings):
        super(EnumSelector, self).__init__()

        self.__parent = parent

        self.__value0 = values[0]
        self.__value = tk.StringVar(self)

        self.__label = ttk.Label(parent, text=text)
        self.__label.grid(row=row, column=0, sticky='W',
                          ** paddings)

        self.__value_sel = ttk.Combobox(parent,
                                        textvariable=self.__value)

        # Initialise with the 1st value of the list of valid values:
        self.__value_sel.set(values[0])
        self.__value_sel.grid(row=row, column=1, sticky='W',
                              **paddings)
        self.__value_sel['values'] = values
        self.__value_sel['state'] = 'readonly'

        self.__value_sel.bind('<<ComboboxSelected>> ', self.__on_value_changed)

    def get(self):
        return self.__value_sel.get()

    def set(self, v):
        self.__value_sel.set(v)
        self.__value0 = v
        print("EnumSelector.set: ", self.__value0, self.__value_sel.get())

    # Called after the value has been successfully saved. The instance is
    # flagged as 'not modified'.
    def config_written(self):
        self.__value0 = self.__value_sel.get()

    # Checks i the value has been modified.
    def is_modified(self):
        print("EnumSelector.is_modified:",
              self.__value0, self.__value_sel.get())
        return self.__value0 != self.__value_sel.get()

    def __on_value_changed(self, event):
        print("EnumSelector.on_value_changed:")
        self.__parent.on_value_changed()


class RootWindow(tk.Tk):
    #
    # Reihenfolge:
    #
    # - Widgets erzeugen; zuerst leer, weil die Werte noch nicht bekannt sind
    #
    # - conf-File lesen und Werte den Widgets zuweisen. Um Änderungen festellen
    #   zu können, sowohl den initialen Wert (Methode set()) und den momentanen
    #   Wert (steht im Widget) merken.
    #
    # - is_modified() vergleicht den momentanen und den initialen Wert.

    DNSproviders = [['Quad9',      '9.9.9.9'],
                    ['Google',     '8.8.8.8'],
                    ['Cloudflare', '1.1.1.1'],
                    ['Other',      '']]
    paddings = {'padx': 10, 'pady': 10}

    #
    # Class constructor
    #
    def __init__(self, config_fn, run_as_root):
        super(RootWindow, self).__init__()

        self.__handlers = {}
        self.__config_fn = config_fn

        self.__create_widgets()
        self.__read_config(self.__config_fn)
        #self.write_config()


    #
    # Read the DNS configuration from /etc/systemd/resolved.conf
    #
    def __read_config(self, fn):
        print("Reading configuration ...")
        try:
            with open(fn, 'r') as ifile:
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
            print("Cannot open", fn, e)


    #
    # Save the modified configuration
    #
    # TODO Handle the case that the original file does not define all keys.
    #
    def __write_config(self):
        try:
            with open('/etc/systemd/resolved.conf', 'r') as f_in:
                with open('/tmp/resolved.conf', 'w') as f_out:
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
                            # TODO Must have a default value; otherwise an
                            # empty value would be written to resolved.conf.
                            f_out.write(
                                      "{}={}\n".format(var, self.__handlers[var].get()))
        except IOErr as e:
            print("Cannot open", e)


    # Tests whether any value has been modified
    def __any_value_modified(self):
        for i in self.__handlers:
            if self.__handlers[i].is_modified():
               return True
        return False


    # Called by widgets when their values changes
    def on_value_changed(self):
        m = self.__any_value_modified()
        print("Value of some widget has changed!", m)
        if m:
            self.b_apply['state'] = tk.NORMAL
        else:
            self.b_apply['state'] = tk.DISABLED


    # Called by widgets when the 'apply' button is pressed
    def __on_apply(self):
        print("on_apply")
        if self.__any_value_modified():
            print("... something changed")
            self.__write_config()
            for i in self.__handlers:
                self.__handlers[i].config_written()
        else:
            print("... nothing changed")
        self.b_apply['state'] = tk.DISABLED


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
                        **RootWindow.paddings)
        self.__handlers['DNS'] = h

        row = row + 1
        h = DNSselector(self, row=row, text='Fallback DNS server',
                        values=RootWindow.DNSproviders,
                        **RootWindow.paddings)
        self.__handlers['FallbackDNS'] = h

        row = row + 1
        h = EnumSelector(self, row=row, text='DNS over TLS',
                         values=['no', 'yes', 'opportunistic'],
                         **RootWindow.paddings)
        self.__handlers['DNSOverTLS'] = h

        row = row + 1
        h = EnumSelector(self, row=row, text='DNSSEC',
                         values=['no', 'yes', 'allow-downgrade'],
                         **RootWindow.paddings)
        self.__handlers['DNSSEC'] = h

        row = row + 1
        h = EnumSelector(self, row=row, text='Quark',
                         values=['no', 'yes', 'allow-downgrade'],
                         **RootWindow.paddings)
        self.__handlers['Quark'] = h

        row = row + 1
        self.b_apply = tk.Button(text="Apply", command=self.__on_apply)
        self.b_apply['state'] = tk.DISABLED
        self.b_apply.grid(row=row, column=2, sticky=tk.E, **RootWindow.paddings)

        button = tk.Button(text="Close", command=quit)
        button.grid(row=row, column=3, sticky=tk.W, **RootWindow.paddings)


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
    print(args)

    root_window = RootWindow(config_fn=args.config,
                             run_as_root=not args.no_root)
    root_window.mainloop()
