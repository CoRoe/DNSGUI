#!/usr/bin/python3

import tkinter as tk
from tkinter import ttk
import re

#
# https://web.archive.org/web/20201112011230/http://effbot.org/tkinterbook/grid.htm
# https://www.pythontutorial.net/tkinter/tkinter-optionmenu/
# https://www.tutorialspoint.com/python/tk_entry.htm
#

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
        p = [q[0] for q in RootWindow.DNSproviders]
        print(p)
        row = 0

        # DNS server address and provider
        label = ttk.Label(self, text='DNS server (e.g. "9.9.9.9")')
        label.grid(row=row, column=0, sticky='W', **RootWindow.paddings)
        self.DNSvar = tk.StringVar(self)
        self.DNSOptionMenu = ttk.OptionMenu(self,
                                            self.DNSvar,
                                            *[q[0] for q in self.DNSproviders])
        self.DNSOptionMenu.grid(row=row, column=1, sticky='W',
                                **RootWindow.paddings)
        self.DNSIPentry = tk. Entry(self)
        self.DNSIPentry.insert(0, self.DNS)
        self.DNSIPentry.grid(row=row, column=2)

        # First fallback DNS server address and provider
        row = row + 1
        label = ttk.Label(self, text='Fallback DNS servers')
        label.grid(row=row, column=0, sticky='W', **RootWindow.paddings)
        self.DNS1var = tk.StringVar(self)
        self.DNS1OptionMenu = ttk.OptionMenu(self,
                                            self.DNS1var,
                                            *[q[0] for q in self.DNSproviders])
        self.DNS1OptionMenu.grid(row=row, column=1, sticky='W',
                                 **RootWindow.paddings)
        self.DNSIP1entry = tk. Entry(self)
        self.DNSIP1entry.insert(0, self.DNS1)
        self.DNSIP1entry.grid(row=row, column=2)

        # Second fallback DNS server address and provider
        row = row + 1
        self.DNS2var = tk.StringVar(self)
        self.DNS2OptionMenu = ttk.OptionMenu(self,
                                            self.DNS2var,
                                            *[q[0] for q in self.DNSproviders])
        self.DNS2OptionMenu.grid(row=row, column=1, sticky='W',
                                 **RootWindow.paddings)
        self.DNSIP2entry = tk. Entry(self)
        self.DNSIP2entry.insert(0, self.DNS2)
        self.DNSIP2entry.grid(row=row, column=2)

        row = row + 1
        label = ttk.Label(self, text='DNS over TLS:')
        label.grid(row=row, column=0, sticky='W', **RootWindow.paddings)
        self.DNSOverTLSvalues = ['no', 'yes', 'opportunistic']
        self.DNSOverTLSvar = tk.StringVar(self)
        self.DNSOverTLSoptionMenu = ttk.OptionMenu(self, self.DNSOverTLSvar,
                                                   self.DNSOverTLSvalues[0],
                                                   *self.DNSOverTLSvalues)
        self.DNSOverTLSoptionMenu.grid(row=row, column=1, sticky=tk.W,
                                       **RootWindow.paddings)

        row = row + 1
        label = ttk.Label(self, text='DNSSEC:')
        label.grid(row=row, column=0, sticky='W',**RootWindow.paddings)
        self.DNSSECvalues = ['no', 'yes', 'allow-downgrade']
        self.DNSSECvar = tk.StringVar(self)
        self.DNSSECoptionMenu = ttk.OptionMenu(self, self.DNSSECvar,
                                               self.DNSSECvalues[0],
                                               *self.DNSSECvalues)
        self.DNSSECoptionMenu.grid(row=row, column=1, sticky=tk.W,
                                   **RootWindow.paddings)

        row = row + 1
        button = tk.Button(text="Apply", command=self.write_config)
        button.grid(row=row, column=2, sticky=tk.E, **RootWindow.paddings)

        button = tk.Button(text="Close", command=quit)
        button.grid(row=row, column=3, sticky=tk.W, **RootWindow.paddings)


if __name__ == '__main__':
    root_window = RootWindow()
    root_window.mainloop()
