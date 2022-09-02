#!/usr/bin/python3

import tkinter as tk
from tkinter import ttk
import re

#
# https://web.archive.org/web/20201112011230/http://effbot.org/tkinterbook/grid.htm
# https://www.pythontutorial.net/tkinter/tkinter-optionmenu/
# https://www.tutorialspoint.com/python/tk_entry.htm
#
# TODO Think of some method
#
#

class DNSselector(tk.Tk):
    def __init__(self, parent, row, text, values, **paddings):
        super(DNSselector, self).__init__()

        self.__parent = parent
        self.__row = row
        self.__text = text
        self.__values = values
        self.__paddings = paddings
        self.__var = tk.StringVar(self)

        self.create_widgets()


    def create_widgets(self):
        # Creates a label with the explanatory text, an option menu (to select
        # the DNS provider), and an entry field (chosen IP address)
        print("create_widgets", self.__text, self.__row)
        self.__label = ttk.Label(self.__parent, text=self.__text)
        self.__label.grid(row=self.__row, column=0, sticky='W',
                          **self.__paddings)

        print([q[0] for q in self.__values])
        self.__var.set('Quad9')

        self.__servers_var = tk.StringVar()
        self.__servers = ttk.Combobox(self.__parent,
                                      textvariable=self.__servers_var)
        self.__servers['values'] = [q[0] for q in self.__values]
        self.__servers['state'] = 'readonly'
        self.__servers.bind('<<ComboboxSelected>>', self.on_server_changed)
        self.__servers.grid(row=self.__row, column=1, sticky='W',
                                **self.__paddings)

        self.__ipaddr_var = tk.StringVar()
        self.__ipaddr = tk.Entry(self.__parent, textvariable=self.__ipaddr_var)
        self.__ipaddr.grid(row=self.__row, column=2)


    def on_server_changed(self, event):
        #print('On server changed', event)
        server = self.__servers_var.get()
        #print("New value:", server)
        i = [q[0] for q in self.__values].index(server)
        ipaddr = self.__values[i][1]
        self.__ipaddr_var.set(ipaddr)


class EnumSelector(tk.Tk):
    def __init__(self, parent, row, text, values, initial_value, **paddings):
        super(EnumSelector, self).__init__()

        self.__parent = parent
        self.__row = row
        self.__text = text
        self.__values = values
        self.__initial_value = initial_value
        self.__paddings = paddings
        self.__value = tk.StringVar(self)
        self.__value.set(initial_value)

        self.create_widgets()


    def create_widgets(self):
        print("EnumSelector", self.__row, self.__text)
        self.__label = ttk.Label(self.__parent, text=self.__text)
        self.__label.grid(row=self.__row, column=0, sticky='W',
                          **self.__paddings)

        self.__value_sel = ttk.Combobox(self.__parent,
                                        textvariable=self.__value)
        self.__value_sel.grid(row=self.__row, column=1, sticky='W',
                          **self.__paddings)
        self.__value_sel.set(self.__initial_value)
        self.__value_sel['values'] = self.__values
        self.__value_sel['state'] = 'readonly'


class RootWindow(tk.Tk):

    DNSproviders = [['Quad9',      '9.9.9.9'],
                    ['Google',     '8.8.8.8'],
                    ['Cloudflare', '1.1.1.1'],
                    ['Other',      '']]
    paddings = {'padx': 10, 'pady': 10}

    #
    # Class constructor
    #
    def __init__(self):
        super(RootWindow, self).__init__()

        # Set default values.
        self.DNS = ''
        self.DNS1 = ''
        self.DNS2 = ''
        self.DNSOverTLS = 'no'
        self.DNSSEC = 'no'

        self.read_config('/etc/systemd/resolved.conf')
        self.create_widgets()

    #
    # Read the DNS configuration from /etc/systemd/resolved.conf
    #
    def read_config(self, fn):
        print("Reading configuration ...")
        try:
            with open(fn, 'r') as ifile:
                for line in ifile:
                    #print(line)
                    # DNS server address in dotted notation
                    m = re.match('^DNS=((\\d+\\.){3}\\d+)', line)
                    if m:
                        self.DNS = m.group(1)
                        print(m.group(1))

                    # One or two addresses in dotted notation, separated by
                    # space.
                    m = re.match('^FallbackDNS=((\\d+\\.){3}\\d+)', line)
                    if m:
                        self.DNS1 = m.group(1)
                        print(m.group(1))

                    m = re.match('^DNSOverTLS=([a-z]+)', line)
                    if m:
                        self.DNSOverTLS = m.group(1)
                        print(m.group(1))

                    m = re.match('^DNSSEC=([a-z]+)', line)
                    if m:
                        self.DNSSEC = m.group(1)
                        print(m.group(1))
        except IOErr as e:
            print("Cannot open", fn, e)

    #
    # Save the modified configuration
    #
    def write_config(self):
        print("Updating configuration ...")
        print("DNSOverTLS", self.DNSOverTLSvar.get())
        print("DNSSEC", self.DNSSECvar.get())

    #
    # Create the widgets and initialise them with the values read from the
    # conf file.
    #
    def create_widgets(self):
        self.title("DNS Configuration")
        #self.minsize(500,400)
        #p = [q[0] for q in RootWindow.DNSproviders]
        #print(p)

        row = 0
        self.x1 = DNSselector(self, row=row, text='DNS server',
                              values=RootWindow.DNSproviders,
                              **RootWindow.paddings)
        row = row + 1
        self.x2 = DNSselector(self, row=row, text='Fallback DNS servers',
                              values=RootWindow.DNSproviders,
                              **RootWindow.paddings)
        row = row + 1
        self.x3 = DNSselector(self, row=row, text='',
                              values=RootWindow.DNSproviders,
                              **RootWindow.paddings)

        row = row + 1
        self.x4 = EnumSelector(self, row=row, text='DNS over TLS',
                               values=['no', 'yes', 'opportunistic'],
                               initial_value = self.DNSOverTLS,
                               **RootWindow.paddings)

        row = row + 1
        self.x5 = EnumSelector(self, row=row, text='DNSSEC',
                               values=['no', 'yes', 'allow-downgrade'],
                               initial_value = self.DNSSEC,
                               **RootWindow.paddings)

        row = row + 1
        button = tk.Button(text="Apply", command=self.write_config)
        button.grid(row=row, column=2, sticky=tk.E, **RootWindow.paddings)

        button = tk.Button(text="Close", command=quit)
        button.grid(row=row, column=3, sticky=tk.W, **RootWindow.paddings)


if __name__ == '__main__':
    root_window = RootWindow()
    root_window.mainloop()
