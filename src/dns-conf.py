#!/usr/bin/python3

from PyQt5.QtGui import *
from PyQt5.QtWidgets import *
from PyQt5.QtCore import *

import re
import os
import subprocess
import argparse
import sys                      # TODO Remove, use argparse


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


class SystemCtl():
    @classmethod
    def status(cls, service):
        print("Querying status of", service)
        p = subprocess.Popen(('/usr/bin/systemctl', 'status',
                                  service),
                                 stdin=subprocess.PIPE,
                                 stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE)
        output = p.communicate()
        print("Return code", p.returncode)
        return p.returncode


class DnsResolverModel():

    def __init__(self, conf_fn):

        if SystemCtl.status("systemd-resolved.service") == 0:
            self.resolver0 = 'systemd-resolved'
        elif SystemCtl.status("portmaster.service") == 0:
            self.__resolver0 = 'portmaster'
        else:
            self.__resolver0 = None

        self.__params0 = {}

        try:
            with open(conf_fn, 'r') as ifile:
                for line in ifile:
                    # Extract key and value.
                    try:
                        m = re.match('^([A-Za-z]+)=([a-z0-9.-]+)', line[:-1])
                        if m:
                            key = m.group(1)
                            value = m.group(2)
                            self.__params0[key] = value
                    except re.error as e:
                        print("RE problem", e)
        except IOError as e:
            print("Cannot open", conf_fn, e)

        self.__resolver = self.__resolver0
        self.__params = self.__params0.copy()


    def save(self, conf_fn, run_ass_root, password=None):
        print("DnsResolverModel.save")
        # Values saved, set status to 'not modified'
        self.__resolver = self.__resolver0
        self.__params = self.__params0.copy()


    def is_modified(self):
        print("DnsResolverModel.is_modified")
        return not (self.__resolver == self.__resolver0 and self.__params == self.__params0)


    def resolver(self):
        return self.__resolver


    def value(self, key):
        if key in self.__params:
            return self.__params[key]
        else:
            return None

    def setValue(self, key, value):
        self.__params[key] = value


class DNSselector():
    """
    Displays a combobox and an entry field side-by-side.

    The combobox allows for selecting a DNS provider (such as Google or Quad9)
    or manually entering an IPv4 address in dotted notation.
    """
    def __init__(self, parent, model, layout, row, text, values):

        self.__parent = parent
        self.__model = model
        self.__values = values
        self.__ipaddr0 = values[0][1]

        # Creates a label with the explanatory text, an option menu (to select
        # the DNS provider), and an entry field (chosen IP address)
        label = QLabel(text)
        layout.addWidget(label, row, 1)
        #label.grid(row=row, column=0, sticky='W', **paddings)

        self.__servers_combo = QComboBox(parent)
        self.__servers_combo.addItems([q[0] for q in values])
        self.__servers_combo.currentTextChanged.connect(self.on_server_changed)
        #self.__servers_combo['state'] = 'readonly'
        #self.__servers_combo.bind('<<ComboboxSelected>>', self.on_server_changed)
        self.__servers_combo.activated.connect(self.on_server_changed)
        layout.addWidget(self.__servers_combo, row, 2)
        #self.__servers_combo.grid(row=row, column=1, sticky='W',
        #                    **paddings)

        #self.__ipaddr_txt = tk.StringVar()
        self.__ipaddr_entry = QLineEdit(parent)
        #self.__ipaddr_entry.grid(row=row, column=2)
        layout.addWidget(self.__ipaddr_entry, row, 3)

        #self.__ipaddr_entry.bind('<Key-Return> ', self.on_ip_changed)
        #self.__ipaddr_entry.bind('<FocusOut> ', self.on_ip_changed)


    def get(self):
        #return self.__ipaddr_txt.get()
        return self.__ipaddr_entry.get()

    def set(self, value):
        self.__ipaddr0 = value
        #print("Set '{}'".format(value))
        #self.__ipaddr_txt.set(value)
        provider = self.__provider_from_ip(value)
        #print(provider)
        self.__servers_combo.setCurrentText(provider)

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
        server = self.__servers_combo.currentText()
        #print("New value:", server)
        i = [q[0] for q in self.__values].index(server)
        ipaddr = self.__ip_from_provider(server)
        self.__ipaddr_entry.setText(ipaddr)
        self.__parent.on_value_changed()


    # Invoked when the IP address might have changed. The method updates the
    # server name according ly.
    def on_ip_changed(self, event):
        ip = self.__ipaddr_txt.get()
        #print("on_ip_changed:", event, ip)
        provider = self.__provider_from_ip(ip)
        #print(provider)
        #self.__servers_var.set(provider)
        self.__servers_combo.set(provider)
        self.__parent.on_value_changed()


    # Called after the value has been successfully saved. The instance is
    # flagged as 'not modified'.
    def config_written(self):
        self.__ipaddr0 = self.__ipaddr_txt.get()


    # Checks if a widget's value has been modified and needs to be saved.
    def is_modified(self):
        #print("DNSselector.is_modified: v0={}, v={}".format(self.__ipaddr0,
        #                                                    self.__ipaddr_txt.get()))
        return self.__ipaddr0 != self.__ipaddr_entry.text()


class EnumSelector():
    def __init__(self, parent, model, layout, row, text, values, key, **paddings):

        self.__parent = parent
        self.__model = model
        self.__key = key
        self.__values = values

        # The initial value. Its purpose is to track if the actual value of
        # the setting is has been modified and needs to be saved.
        #
        # - Initialised to the 1st element of the 'values' parameter of the
        #   constructor.
        #
        # - Updated to the current value when the configuration file is saved.
        self.__value0 = values[0]

        self.__label = QLabel(text)
        layout.addWidget(self.__label, row, 1)
        #self.__label.grid(row=row, column=0, sticky='W',
        #                  **paddings)

        self.__value_combo = QComboBox(parent)

        # Initialise with the 1st value of the list of valid values:
        #self.__value_combo.set(values[0])
        layout.addWidget(self.__value_combo, row, 2)
        #self.__value_combo.grid(row=row, column=1, sticky='W',
        #                        **paddings)
        #self.__value_combo['values'] = values
        self.__value_combo.addItems(values)
        #self.__value_combo['state'] = 'readonly'

        #self.__value_combo.bind('<<ComboboxSelected>> ',
        #                        self.__on_value_changed)
        self.__value_combo.currentIndexChanged.connect(self.__on_value_changed)

    def get(self):
        return self.__value_combo.get()

    def set(self, v):
        self.__value_combo.setCurrentText(v)
        self.__value0 = v
        #print("EnumSelector.set: ", self.__value0, self.__value_combo.get())

    # Called after the value has been successfully saved. The instance is
    # flagged as 'not modified'.
    def config_written(self):
        self.__value0 = self.__value_combo.get()

    # Checks i the value has been modified.
    def is_modified(self):
        #print("EnumSelector.is_modified:",
        #      self.__value0, self.__value_combo.get())
        return self.__value0 != self.__value_combo.currentText()

    def __on_value_changed(self, index):
        print("EnumSelector.on_value_changed:", self.__key, self.__values[index], index)
        self.__model.setValue(self.__key, self.__values[index])
        self.__parent.on_value_changed()




class MainGuiWindow(QMainWindow):
    """ Main application window.
    """

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
                    ['DNSforge',   '176.9.93.198'],
                    ['Google',     '8.8.8.8'],
                    ['Cloudflare', '1.1.1.1'],
                    ['Other',      '']]
    __paddings = {'padx': 10, 'pady': 10}
    __tmp_fn = '/tmp/resolved.conf'
    __resolved_service = 'systemd-resolved'


    #
    # Class constructor
    #
    def __init__(self, model, config_fn, run_as_root, script_path):
        super(MainGuiWindow, self).__init__()

        self.__run_as_root = run_as_root
        self.__script_path = script_path
        self.__helper_path = self.__script_path.replace(".py", ".helper.sh")
        self.__config_fn = config_fn
        self.__model = model
        self.__password = None

        self.__handlers = {}
        #self.__check_preconditions()
        self.__create_widgets(model)
        self.__read_config(self.__config_fn)


    #
    # Read the DNS configuration from /etc/systemd/resolved.conf
    #
    def __read_config(self, conf_fn):
        #print("Reading configuration ...")
        try:
            with open(conf_fn, 'r') as ifile:
                for line in ifile:
                    # Extract key and value.
                    try:
                        m = re.match('^([A-Za-z]+)=([a-z0-9.-]+)', line[:-1])
                        if m:
                            key = m.group(1)
                            value = m.group(2)
                            # If a widget is defined for the particular key
                            # then call the set() method of the widget.
                            if key in self.__handlers:
                                self.__handlers[key].set(value)
                    except re.error as e:
                        print("RE problem", e)
        except IOError as e:
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
                            #print("Missing:", var)
                            f_out.write(
                                      "{}={}\n".format(var,
                                                       self.__handlers[var].get()))
        except IOErr as e:
            print("Cannot open", e)


    # Tests whether any value has been modified
    def __any_value_modified(self):
        """ Tests whether any of the embedded objects has changed."""
        for i in self.__handlers:
            if self.__handlers[i].is_modified():
               return True
        return False


    # Called by widgets when their values change
    def on_value_changed(self):
        m = self.__model.is_modified()
        #print("Value of some widget has changed!", m)
        if m:
            # Modified, enable 'apply' button and set focus to it.
            #self.__b_apply['state'] = tk.NORMAL
            self.__b_apply.setEnabled(True)
            self.__b_apply.setFocus()
        else:
            # Nothing modified; disable 'apply' button and set focus to 'close'.
            #self.__b_apply['state'] = tk.DISABLED
            self.__b_apply.setEnabled(False)
            self.__b_close.setFocus()


    def __on_apply(self):
        """
        Called when the 'apply' button is pressed.
        """

        if self.__model.is_modified():
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
                    self.__write_config(self.__config_fn, MainGuiWindow.__tmp_fn)
                    # ... copy the temp file to /etc and restart the daemon
                    if not self.__update_conf_file():
                        return
                    #self.__run_helper_script(True)
                    for i in self.__handlers:
                        self.__handlers[i].config_written()
                    self.__b_apply['state'] = tk.DISABLED
                    self.__b_close.setFocus()
            else:
                # Run as normal user
                # Write modified values to a temp file and ...
                #self.__write_config(self.__config_fn, MainGuiWindow.__tmp_fn)
                self.__model.save(self.__config_fn, self.__run_as_root)
                self.on_value_changed()
        else:
            print("... nothing changed")


    def __on_close(self):
        """
        Close button pressed
        """
        #if self.__any_value_modified():
        if self.__model.is_modified():
            answer = QMessageBox.question(self,
                                          'Exit Application',
                                           'Discard changes?',
                                           QMessageBox.Yes | QMessageBox.No)
            if answer == QMessageBox.Yes:
                #print("Discarding changes")
                QCoreApplication.quit()
        else:
            QCoreApplication.quit()


    def __on_return_event(self, event):
        if event.widget == self.__b_apply:
            self.__on_apply()
        elif event.widget == self.__b_close:
            self.__on_close()


    def __on_systemd_resolver_changed(self, x):
        s = self.__systemd_resolver.checkState()
        if s:
            self.__portmaster.setChecked(False)


    def __on_portmaster_changed(self, x):
        s = self.__portmaster.checkState()
        if s:
            self.__systemd_resolver.setChecked(False)


    #
    # Create the widgets and initialise them with the values read from the
    # conf file.
    #
    def __create_widgets(self, model):
        assert(type(model) == DnsResolverModel)

        self.setWindowTitle("DNS Configuration")

        main_layout = QVBoxLayout()
        config_area = QGridLayout()
        button_area = QHBoxLayout()
        widget = QWidget()
        #widget.setLayout(main_layout)

        self.__systemd_resolver = QCheckBox("Systemd Resolver", widget)
        #s = SystemCtl.status("systemd-resolved.service")
        if model.resolver() == 'systemd-resolved':
            self.__systemd_resolver.setChecked(True)
        self.__systemd_resolver.stateChanged.connect(self.__on_systemd_resolver_changed)
        main_layout.addWidget(self.__systemd_resolver)

        row = 0
        # parent, model, layout, row, text, values
        h = DNSselector(self, model, config_area, row=row, text='DNS server',
                        values=MainGuiWindow.DNSproviders)
        self.__handlers['DNS'] = h

        row = row + 1
        h = DNSselector(self, model, config_area, row=row, text='Fallback DNS server',
                        values=MainGuiWindow.DNSproviders)
        self.__handlers['FallbackDNS'] = h

        row = row + 1
        # parent, layout, row, text, values, key, **paddings
        h = EnumSelector(self, model, config_area, row, 'DNS over TLS',
                         ['no', 'yes', 'opportunistic'], 'DNSOverTLS')
        self.__handlers['DNSOverTLS'] = h

        row = row + 1
        h = EnumSelector(self, model, config_area, row, 'DNSSEC',
                         ['no', 'yes', 'allow-downgrade'], 'DNSSEC',)
        self.__handlers['DNSSEC'] = h

        row = row + 1
        self.__b_apply = QPushButton(text="Apply")
        self.__b_apply.clicked.connect(self.__on_apply)
        #self.__b_apply['state'] = tk.DISABLED
        #self.__b_apply.grid(row=row, column=2, sticky=tk.E,
        #                    **MainGuiWindow.__paddings)
        button_area.addWidget(self.__b_apply)

        self.__b_close = QPushButton(text="Close")
        self.__b_close.clicked.connect(self.__on_close)
        #self.__b_close.grid(row=row, column=3, sticky=tk.W,
        #                    **MainGuiWindow.__paddings)
        button_area.addWidget(self.__b_close)
        #self.__b_close.setFocus()

        #self.bind('<Return>', self.__on_return_event)
        main_layout.addLayout(config_area)

        self.__portmaster = QCheckBox("Portmaster", widget)
        if model.resolver() == 'portmaster':
            self.__portmaster.setChecked(True)
        self.__portmaster.stateChanged.connect(self.__on_portmaster_changed)

        main_layout.addWidget(self.__portmaster)

        main_layout.addLayout(button_area)
        widget.setLayout(main_layout)
        self.setCentralWidget(widget)


    def __update_conf_file(self):
        """ Updates the conf file in /etc.

        Steps are:
        - Copy conf file to backup file
        - Copy temp file to conf file
        - Restart resolver0 service
        """

        try:
            # Copy conf file to backup file
            p = subprocess.Popen(('/usr/bin/sudo', '-S', '-p', '', 'cp',
                                  self.__config_fn, self.__config_fn + '.bak'),
                                 stdin=subprocess.PIPE,
                                 stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE)
            output = p.communicate(self.__password.encode())
            #print("__update_conf_file return code:", p.returncode,
            #      output[0], output[1])
            if p.returncode != 0:
                QMessageBox.showerror("Error", output[1])
                return False

            # Copy temp file to conf file
            p = subprocess.Popen(('/usr/bin/sudo', '-S', '-p', '', 'cp',
                                  self.__tmp_fn, self.__config_fn),
                                 stdin=subprocess.PIPE,
                                 stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE)
            output = p.communicate(self.__password.encode())
            #print("__update_conf_file return code:", p.returncode,
            #      output[0], output[1])
            if p.returncode != 0:
                QMessageBox.showerror("Error", output[1])
                return False

            # Restart the resolver0 service
            p = subprocess.Popen(('/usr/bin/sudo', '-S', '-p', '',
                                  'systemctl', 'restart',
                                  'systemd-resolved.service'),
                                 stdin=subprocess.PIPE,
                                 stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE)
            output = p.communicate(self.__password.encode())
            #print("__update_conf_file return code:", p.returncode,
            #      output[0], output[1])
            if p.returncode != 0:
                QMessageBox.showerror("Error", output[1])
                return False

            return True

        except Exception as e:
            print("__update_conf_file exception", e)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Display and modify settings '
                                     'of the systemd DNS resolver0.')
    parser.add_argument('--config',
                        default='/etc/systemd/resolved.conf',
                        help='path of the conf file; defaults '
                        'to /etc/systemd/resolved.conf')
    parser.add_argument('--no-root',
                        action='store_true',
                        help='do not run as root; default is to run as root')
    args = parser.parse_args()

    model = DnsResolverModel(args.config)
    app = QApplication(sys.argv)
    root_window = MainGuiWindow(model, config_fn=args.config,
                                run_as_root=not args.no_root,
                                script_path=os.path.abspath( __file__ ))
    root_window.show()
    app.exec_()
