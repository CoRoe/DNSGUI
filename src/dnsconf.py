#!/usr/bin/python3

"""Simple graphical tool to configure DNS resolvers on Ubuntu and similar
platforms.

"""

from PyQt5.QtWidgets import (QMessageBox, QLabel, QLineEdit, QComboBox,
                             QMainWindow, QApplication, QInputDialog,
                             QWidget, QGridLayout, QHBoxLayout, QVBoxLayout,
                             QPushButton, QGroupBox)
from PyQt5.QtCore import Qt, QCoreApplication

import regex as re
import os
import subprocess
import argparse
import sys
from magic.compat import NONE


#
# TODO: Allow white space around the '=' signs in the configuration file.
#
# TODO: Assign default values to all variables so that they have sensible
# values even when not present in resolved.conf.
#


class SystemdService():

    # The two services managed by this application
    SVC_PORTMASTER = 'portmaster.service'
    SVC_SYSTEMD_RESOLVED = 'systemd-resolved.service'

    @classmethod
    def status(cls, service: str) -> int:
        """ Queries the status of a service.
        """
        print("Querying status of", service)
        p = subprocess.Popen(('/usr/bin/systemctl', 'status', service),
                             stdin=subprocess.PIPE,
                             stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE)
        p.communicate()
        print("Return code", p.returncode)
        return p.returncode


    @classmethod
    def activate(cls, service, password):
        # First enable the service
        p = subprocess.Popen(('/usr/bin/sudo', '-S', '-p', '',
                              'systemctl', 'enable', service),
                             stdin=subprocess.PIPE,
                             stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE)
        output = p.communicate(password.encode())
        if p.returncode != 0:
            QMessageBox.critical(None, "Error", str(output[1]))
            return False

        # Then start
        p = subprocess.Popen(('/usr/bin/sudo', '-S', '-p', '',
                              'systemctl', 'start', service),
                             stdin=subprocess.PIPE,
                             stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE)
        output = p.communicate(password.encode())
        if p.returncode != 0:
            QMessageBox.critical(None, "Error", str(output[1]).encode)
            return False
        return True


    @classmethod
    def deactivate(cls, service, password):
        # First stop the service
        p = subprocess.Popen(('/usr/bin/sudo', '-S', '-p', '',
                              'systemctl', 'stop', service),
                             stdin=subprocess.PIPE,
                             stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE)
        output = p.communicate(password.encode())
        if p.returncode != 0:
            QMessageBox.critical(None, "Error", str(output[1]).encode)
            return False

        # Then disable
        p = subprocess.Popen(('/usr/bin/sudo', '-S', '-p', '',
                              'systemctl', 'disable', service),
                             stdin=subprocess.PIPE,
                             stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE)
        output = p.communicate(password.encode())
        if p.returncode != 0:
            QMessageBox.critical(None, "Error", str(output[1]).encode)
            return False

        return True


class ResolvedConfig():
    """Models the configuration file.

    Contains methods to read the read the configuration from a file, to save it to
    a file, to set and get individual parameters, and to check if the configuration
    has been changed since it has been saved.

    TODO: Do we need conf0?
    """

    def __init__(self, conf_fn, run_as_root):
        self.__conf_fn = conf_fn
        self.__run_as_root = run_as_root
        self.__conf = self.__read_from_file()
        self.__conf0 = self.__conf.copy()


    def params(self):
        """Return the systemd-resolved configuration parameters."""
        return self.__conf


    @classmethod
    def runShellCommandAsRoot(cls, password, cmd, *args):
        """ Run a shell command as root.
        """
        execargs = ['/usr/bin/sudo', '-S', '-p', '']
        execargs.append(cmd)
        for arg in args:
            execargs.append(arg)
        print("Running", execargs)
        p = subprocess.Popen((execargs),
                             stdin=subprocess.PIPE,
                             stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE)
        output = p.communicate(password.encode())
        print("Popen:", str(output[1]))
        return p.returncode


    def __read_from_file(self):
        """ Read the systemd-resolved configuration file and return it."""
        try:
            params = {}

            with open(self.__conf_fn, 'r') as ifile:
                for line in ifile:
                    # Extract key and getSystemdResolvedParameter.
                    try:
                        m = re.match('^([A-Za-z]+)=([a-z0-9.-]+)', line[:-1])
                        if m:
                            key = m.group(1)
                            value = m.group(2)
                            params[key] = value
                    except re.error as e:
                        print("RE problem", e)
        except IOError as e:
            print("Cannot open", self.__conf_fn, e)
        return params


    def save(self, password=None) -> bool:
        """ Save the systemd-resolved configuration in a file.
        Copies the content of the configuration file to a temporary file,
        replacing the changed values. After that, the temporary file
        is copied to the configuration file; this requires root privileges.
        """
        tmp_fn = '/tmp/resolv.conf'

        if self.__run_as_root: assert(password)

        print("DNSConfigurationModel.save")
        try:
            with open(self.__conf_fn, 'r') as f_in:
                with open(tmp_fn, 'w') as f_out:
                    updated_vars = set()
                    for line in f_in:
                        m = re.match('^([A-Za-z]+)=', line)
                        if m:
                            var = m.group(1)
                            if var in self.__conf:
                                f_out.write(
                                      "{}={}\n".format(var, self.__conf[var]))
                                updated_vars.add(var)
                            else:
                                f_out.write(line)
                        else:
                            f_out.write(line)
                    # resolved.conf might not define all
                    for var in self.__conf:
                        if not var in updated_vars:
                            if verbose: print("Missing:", var)
                            f_out.write(
                                      "{}={}\n".format(var,
                                                       self.__conf[var]))
            if self.__run_as_root:
                rc = ResolvedConfig.runShellCommandAsRoot(password, 'cp', tmp_fn, self.__conf_fn)

            else:
                rc = os.system('cp ' + tmp_fn + ' ' + self.__conf_fn)

            if rc == 0:
                self.__conf0 = self.__conf.copy()
            else:
                msg = f"Could not update '{self.__conf_fn}'; copy process terminated with {rc}"
                QMessageBox.critical(None, "Error", msg)

            return rc == 0


        except IOError as e:
            print("Cannot open", e)
            return False


    def getSystemdResolvedParameter(self, key):
        """ Return the parameter associated with 'key'. """
        if key in self.__conf:
            return self.__conf[key]
        else:
            return None


    def setResolvedParameter(self, key, value):
        """ Set the parameter associated with 'key'. """
        self.__conf[key] = value


    def value(self, key):
        try:
            value = self.__conf[key]
        except:
            value = None
        return value


    def isModified(self):
        modified = self.__conf != self.__conf0
        return modified


class DNSConfigurationModel():
    """ Models the data that is visualized by the DNSConfigurationrView.

    It has three components: Two services and a configuration file for one
    of the services. Normally, only one of the services should be active at any given time.
    At application start, however, 0, 1, or 2 of the resolver services may be active.

    If the configuration is changed then the related service must be restarted.

    This model keeps track of which DNS resolver service is active (__resolvers and __resolvers0)
    and the resolver parameters (__systemdResolvedParams and __systemdResolvedParams0).

    Exports the functions:

        Get status: Returns a list with all currently active resolver services

        Get resolver parameters: returns the set of resolver parameters (a dict)

        Set resolver parameter: Set a single parameters

        Activate: Activates one resolver service and deactivates the other

        Apply changes: Commits all changes - saves parameters to the configuration file and
        stops / starts resolver services. If only the parameters have changed then the
        related service is restarted.

    Internal status:

        Set of active resolver services

        Resolver parameters

    """
    def __init__(self, conf_fn, run_as_root):
        """ Create the model, populating it with data read from configuration
        files and systemd service status.
        """

        # Create the component objects
        self.__systemd_resolved_config = ResolvedConfig(conf_fn, run_as_root)

        #self.__readResolverStatus()

        #self.__run_as_root = run_as_root
        self.__resolvers = self.__activeResolvers()
        self.__resolvers0 = self.__resolvers.copy()
        #self.__systemdResolvedParams = self.__systemd_resolved_config.params()
        #self.__systemdResolvedParams0 = self.__systemdResolvedParams.copy()


    def __activeResolvers(self) -> set[str]:
        """Query the status of all systed resolver services and return their names as a set."""
        n = set()
        if SystemdService.status(SystemdService.SVC_PORTMASTER) == 0:
            n.add(SystemdService.SVC_PORTMASTER)
        if SystemdService.status(SystemdService.SVC_SYSTEMD_RESOLVED) == 0:
            n.add(SystemdService.SVC_SYSTEMD_RESOLVED)
        return n


    def save(self, run_as_root, passwd):
        """Save the model state.

        If the configuration has been modified then save it first.
        """
        self.__systemd_resolved_config.save(passwd)

        if self.__resolvers != self.__resolvers0:
            # Für alle Services:
            #   Wenn der Service nicht aktiv sein soll, deaktivieren
            #   Sonst aktivieren
            print(f"save(): resolvers: {self.__resolvers}")
            for s in [SystemdService.SVC_PORTMASTER, SystemdService.SVC_SYSTEMD_RESOLVED]:
                if s in self.__resolvers:
                    print(f"activate {s}")
                    SystemdService.activate(s, passwd)
                else:
                    print(f"deactivate {s}")
                    SystemdService.deactivate(s, passwd)
            self.__resolvers0 = self.__resolvers.copy()


    def isModified(self):
        """ Check if the model has been modified. """
        print('resolvers0 =', self.__resolvers0, 'resolvers =', self.__resolvers)
        modified = self.__resolvers != self.__resolvers0 or self.__systemd_resolved_config.isModified()
        print(f"DNSConfigurationModel.isModified: {modified}")
        return modified


    def resolvers(self):
        """ Returns a set of the names of the current resolvers."""
        return self.__resolvers


    def setResolver(self, resolver, check_state):
        """ Sets the currently active resolver."""
        assert resolver in (SystemdService.SVC_SYSTEMD_RESOLVED, SystemdService.SVC_PORTMASTER)
        #self.__resolvers = set([resolver])
        if check_state:
            print(f"setResolver: add {resolver}")
            self.__resolvers.add(resolver)
        else:
            print(f"setResolver: remove {resolver}")
            if resolver in self.__resolvers:
                self.__resolvers.remove(resolver)
        print(f"--> {self.__resolvers}")


    def getDNSConf_unused(self, key):
        if key in self.__systemdResolvedParams:
            return self.__systemdResolvedParams[key]
        else:
            return None


    def getDNSConf(self, key):
        value = self.__systemd_resolved_config.value(key)
        return value


    def setResolvedParameter(self, key, value):
        print(f"SetResolvedParameter({key}, {value})")
        #self.__systemdResolvedParams[key] = value
        self.__systemd_resolved_config.setResolvedParameter(key, value)


class DNSselector():
    """
    Displays a combobox and an entry field side-by-side.

    The combobox allows for selecting a DNS provider (such as Google or Quad9)
    or manually entering an IPv4 address in dotted notation.
    """
    def __init__(self, view, model, layout, row, text, values, key):

        assert(type(view) == DNSConfigurationView)
        self.__view = view
        assert(type(model) == DNSConfigurationModel)
        self.__model = model
        assert(type(key) == str)
        self.__key = key
        assert(type(values) == list)
        self.__values = values

        ip = model.getDNSConf(key)
        provider = self.__providerFromIp(ip)

        # Creates a label with the explanatory text, an option menu (to select
        # the DNS provider), and an entry field (chosen IP address)
        label = QLabel(text)
        layout.addWidget(label, row, 1)

        self.__servers_combo = QComboBox(view)
        self.__servers_combo.addItems([q[0] for q in values])
        self.__servers_combo.setCurrentText(provider)
        self.__servers_combo.currentTextChanged.connect(self.__onProviderChanged)
        layout.addWidget(self.__servers_combo, row, 2)

        self.__ipaddr_entry = QLineEdit(view)
        self.__ipaddr_entry.setText(ip)
        self.__ipaddr_entry.textEdited.connect(self.__onIpChanged)
        layout.addWidget(self.__ipaddr_entry, row, 3)


    def __providerFromIp(self, ip):
        """ Given an IP address return the provider name. Return 'Other' if no
        matching IP address is found."""
        for pair in self.__values:
            if pair[1] == ip:
                return pair[0]
        return 'Other'


    # Given a provide name return the IP address
    def __ipFromProvider(self, prov):
        """ Given an provider name return the IP address of its nameserver. """
        for pair in self.__values:
            if pair[0] == prov:
                return pair[1]
        return ''

    # Invoked when the user selects a new server. The method updates the IP
    # address accordingly.
    def __onProviderChanged(self, server):
        """ Called by a server selection widget when the selection has changed.

        Notifies the view of the change.
        """
        print('DNSselector: On server changed; new server is', server)
        if not server == 'Other':
            ipaddr = self.__ipFromProvider(server)
            self.__ipaddr_entry.setText(ipaddr)
            self.__model.setResolvedParameter(self.__key, ipaddr)
            self.__view.updateButtonStatus()


    # Invoked when the IP address might have changed. The method updates the
    # server name according ly.
    def __onIpChanged(self, ip):
        print("DNSselector: on ip changed; new ip is", ip)
        provider = self.__providerFromIp(ip)
        self.__servers_combo.setCurrentText(provider)
        self.__model.setResolvedParameter(self.__key, ip)
        self.__view.updateButtonStatus()


class EnumSelector():
    """Wrapper class for a list widget.

    When the user changes the selection, the wrapper updates the model and
    calls an 'on change' callback of the parent object.

    """
    def __init__(self, parent, model, layout, row, text, values, key):

        self.__view = parent
        self.__model = model
        self.__key = key
        self.__values = values

        # The initial getSystemdResolvedParameter. Its purpose is to track if the actual getSystemdResolvedParameter of
        # the setting is has been modified and needs to be saved.
        #
        # - Initialised to the 1st element of the 'values' parameter of the
        #   constructor.
        #
        # - Updated to the current getSystemdResolvedParameter when the configuration file is saved.
        self.__value0 = values[0]

        self.__label = QLabel(text)
        layout.addWidget(self.__label, row, 1)
        self.__value_combo = QComboBox(parent)

        # Initialise with the 1st getSystemdResolvedParameter of the list of valid values:
        layout.addWidget(self.__value_combo, row, 2)
        self.__value_combo.addItems(values)
        self.__value_combo.setCurrentText(self.__model.getDNSConf(key))
        self.__value_combo.currentIndexChanged.connect(self.__onValueChanged)


    def __onValueChanged(self, index):
        print("EnumSelector.updateButtonStatus:", self.__key, self.__values[index], index)
        self.__model.setResolvedParameter(self.__key, self.__values[index])
        self.__view.updateButtonStatus()


class DNSConfigurationView(QMainWindow):
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
    # - isModified() vergleicht den momentanen und den initialen Wert.

    DNSproviders = [['Quad9',      '9.9.9.9'],
                    ['DNSforge',   '176.9.93.198'],
                    ['dismail',    '116.203.32.217'],
                    ['Google',     '8.8.8.8'],
                    ['Cloudflare', '1.1.1.1'],
                    ['Other',      '']]

    #
    # Class constructor
    #
    def __init__(self, model, config_fn, run_as_root):
        super(DNSConfigurationView, self).__init__()

        self.__run_as_root = run_as_root
        self.__config_fn = config_fn
        self.__model = model
        self.__password = None

        self.__createWidgets(model)
        self.updateButtonStatus()             # Convenient way to set button status


    def updateButtonStatus(self):
        """ Update 'apply' and 'close buttons according to the state of
        the model.

        Widgets should call this method after each user interaction.
        """
        m = self.__model.isModified()
        if verbose: print("updateButtonStatus: Value of some widget has changed!", m)
        if m:
            # Modified, enable 'apply' button and set focus to it.
            self.__b_apply.setEnabled(True)
            self.__b_apply.setDefault(True)
            self.__b_apply.setFocus()
        else:
            # Nothing modified; disable 'apply' button and set focus to 'close'.
            self.__b_apply.setEnabled(False)
            self.__b_apply.setDefault(True)
            self.__b_close.setFocus()


    def __updateDisplayedResolver(self):
        """ Update the check mark of the group boxes to reflect the currently active
        resolver. The info is retrieved from the model.
        """
        resolvers = self.__model.resolvers()
        self.__sysd_group.setChecked(SystemdService.SVC_SYSTEMD_RESOLVED in resolvers)
        self.__portmaster.setChecked(SystemdService.SVC_PORTMASTER in resolvers)


    def __onApply(self):
        """
        Called when the 'apply' button is pressed.
        """

        if self.__model.isModified():
            print("... something changed")
            self.setCursor(Qt.WaitCursor)
            if self.__run_as_root:
                # If the password has been previously set don't ask again
                if not self.__password:
                    self.__password, done = QInputDialog.getText(
                        self, 'Password required', 'Enter your password:',
                        echo=QLineEdit.Password)
                    # If the user has actually entered a password then proceed.
                    if not done:
                        # No password entered
                        self.__password = None

            if self.__run_as_root:
                # Run as root
                if self.__password:
                    self.__model.save(self.__run_as_root, self.__password)
                else:
                    if verbose: print("No password specified")
            else:
                # Run as normal user
                self.__model.save(self.__config_fn, self.__run_as_root)
            self.__updateDisplayedResolver()
            self.updateButtonStatus()
            self.unsetCursor()
        else:
            if verbose: print("... nothing changed")


    def __onClose(self):
        """
        Close button pressed
        """
        if self.__model.isModified():
            answer = QMessageBox.question(self,
                                          'Exit Application',
                                           'Discard changes?',
                                           QMessageBox.Yes | QMessageBox.No)
            if answer == QMessageBox.Yes:
                if verbose: print("Discarding changes")
                QCoreApplication.quit()
        else:
            QCoreApplication.quit()


    def __onSystemdResolverToggled(self, check_state):
        """ Called when the user toggles the 'systemd-resolved' check mark."""
        print("Systemd resolver clicked: ", check_state)
        if check_state:
            #self.__portmaster.setChecked(False)
            #self.__model.portmasterDisable()
            #self.__model.systemdResolvedEnable()
            #self.__updateDisplayedResolver()
            pass
        self.__model.setResolver(SystemdService.SVC_SYSTEMD_RESOLVED, check_state)
        self.updateButtonStatus()


    def __onPortmasterToggled(self, checkState):
        """ Called when the user toggle the 'portmaster' check mark."""
        #checkState = self.__portmaster.checkState()
        print("Portmaster clicked:", checkState)
        if checkState:
            #self.__sysd_group.setChecked(False)
            #self.__model.portmasterEnable()
            #self.__model.systemdResolvedDisable()
            #self.__updateDisplayedResolver()
            pass
        self.__model.setResolver(SystemdService.SVC_PORTMASTER, checkState)
        self.updateButtonStatus()


    #
    # Create the widgets and initialise them with the values read from the
    # conf file.
    #
    def __createWidgets(self, model):
        assert(type(model) == DNSConfigurationModel)

        self.setWindowTitle("DNS Resolver Configuration")

        widget = QWidget()

        main_layout = QVBoxLayout()
        sysd_grid = QGridLayout()

        # Create the wrapper objects of the widgets.
        #
        # Note that they have to be assigned to some instance variables; if
        # they weren't, garbage collection would free the objects and the
        # widgets won't work properly.
        row = 0
        self.__DNS = DNSselector(self, model, sysd_grid, row, 'DNS server',
                        DNSConfigurationView.DNSproviders, 'DNS')

        row = row + 1
        self.__DNSFallback = DNSselector(self, model, sysd_grid, row,
                                         'Fallback DNS server',
                                         DNSConfigurationView.DNSproviders,
                                         'FallbackDNS')

        row = row + 1
        self.__DoT= EnumSelector(self, model, sysd_grid, row, 'DNS over TLS',
                                 ['no', 'yes', 'opportunistic'],
                                 'DNSOverTLS')

        row = row + 1
        self.__DNSSEC = EnumSelector(self, model, sysd_grid, row, 'DNSSEC',
                                     ['no', 'yes', 'allow-downgrade'],
                                     'DNSSEC',)

        #resolvers = self.__model.resolvers()
        self.__sysd_group = QGroupBox("Systemd-resolved", widget)
        self.__sysd_group.setCheckable(True)
        #self.__sysd_group.setChecked(SystemdService.SVC_SYSTEMD_RESOLVED in resolvers)
        self.__sysd_group.toggled.connect(self.__onSystemdResolverToggled)
        self.__sysd_group.setLayout(sysd_grid)
        main_layout.addWidget(self.__sysd_group)

        self.__portmaster = QGroupBox("Portmaster", widget)
        self.__portmaster.setCheckable(True)
        #self.__portmaster.setChecked(SystemdService.SVC_PORTMASTER in resolvers)
        self.__portmaster.toggled.connect(self.__onPortmasterToggled)

        main_layout.addWidget(self.__portmaster)

        button_area = QHBoxLayout()
        self.__b_apply = QPushButton(widget, text="Apply")
        self.__b_apply.clicked.connect(self.__onApply)
        button_area.addWidget(self.__b_apply)

        self.__b_close = QPushButton(widget, text="Close")
        self.__b_close.setDefault(True)
        self.__b_close.clicked.connect(self.__onClose)
        button_area.addWidget(self.__b_close)

        main_layout.addLayout(button_area)
        widget.setLayout(main_layout)
        self.setCentralWidget(widget)

        self.__updateDisplayedResolver()


if __name__ == '__main__':
    description = """ Switch between DNS resolvers.

The system will use either systemd-resolved or portmaster. The user can edit
some of the systemd-resolved parameters.  Starting an stopping services and
write access to the configuration file require root privileges. The
application uses sudo to execute the operations and therefore queries the
user's password.  """
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument('--config',
                        default='/etc/systemd/resolved.conf',
                        help='path of the conf file; defaults '
                        'to /etc/systemd/resolved.conf')
    parser.add_argument('--no-root',
                        action='store_true',
                        help='do not run as root; default is to run as root')
    parser.add_argument('--verbose',
                        action='store_true',
                        help='print debug info')
    args = parser.parse_args()

    global verbose
    verbose = args.verbose

    model = DNSConfigurationModel(args.config, not args.no_root)
    app = QApplication(sys.argv)
    root_window = DNSConfigurationView(model, config_fn=args.config,
                                run_as_root=not args.no_root)
    root_window.show()
    app.exec_()
