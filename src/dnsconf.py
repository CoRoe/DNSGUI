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


#
# TODO Don't rewrite the configuration file if only the local resolver has
# changed.
#
# TODO: Handle the error case that both resolvers are running.
#
# TODO: Allow white space around the '=' signs in the configuration file.
#
# TODO: Assign default values to all variables so that they have sensible
# values even when not present in resolved.conf.
#


class SystemCtl():
    """ Deals with systemd services.
    """
    SVC_PORTMASTER = 'portmaster.service'
    SVC_SYSTEMD_RESOLVED = 'systemd-resolved.service'

    @classmethod
    def status(cls, service):
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
    def startOrStop(cls, command, service, password=None) -> bool:
        """ Enables or disables a systemctl service. If a password is specified
            then sudo is used and the password is piped into sudo.
        """
        assert(command in ('start', 'stop', 'restart'))
        en_disable = 'enable' if command == 'start' else 'disable'
        print("startOrStop", en_disable, '--now', service)
        if password:
            p = subprocess.Popen(('/usr/bin/sudo', '-S', '-p', '',
                                  'systemctl', en_disable, '--now', service),
                                 stdin=subprocess.PIPE,
                                 stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE)
            output = p.communicate(password.encode())
        else:
            p = subprocess.Popen(('systemctl', en_disable, '--now', service),
                                 stdin=subprocess.PIPE,
                                 stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE)
            output = p.communicate()
        if p.returncode != 0:
            QMessageBox.critical(None, "Error", str(output[1]))
            return False

        return True


class DNSConfigurationModel():
    """ Models the data that is visualized by the DNSConfigurationrView.
    """
    def __init__(self, conf_fn):
        """ Create the model, populating it with data read from configuration
        files and systemd service status.
        """

        self.__conf_fn = conf_fn
        self.__systemdResolvedParams = {}

        self.__readResolverStatus()
        self.__readSysdResolvedConfiguration()

        self.__resolver0 = self.__resolver
        self.__systemdResolvedParams0 = self.__systemdResolvedParams.copy()


    def __readResolverStatus(self):
        """ Get the status of the resolver services and store it in the model."""
        if SystemCtl.status(SystemCtl.SVC_SYSTEMD_RESOLVED) == 0:
            self.__resolver = SystemCtl.SVC_SYSTEMD_RESOLVED
        elif SystemCtl.status(SystemCtl.SVC_PORTMASTER) == 0:
            self.__resolver = SystemCtl.SVC_PORTMASTER
        else:
            self.__resolver = None
        return True


    def __readSysdResolvedConfiguration(self):
        """ Read the systemd-resolved configuration file and store
        its values in the model."""
        try:
            with open(self.__conf_fn, 'r') as ifile:
                for line in ifile:
                    # Extract key and getSystemdResolvedParameter.
                    try:
                        m = re.match('^([A-Za-z]+)=([a-z0-9.-]+)', line[:-1])
                        if m:
                            key = m.group(1)
                            value = m.group(2)
                            self.__systemdResolvedParams[key] = value
                    except re.error as e:
                        print("RE problem", e)
        except IOError as e:
            print("Cannot open", self.__conf_fn, e)
        return True


    def __saveSysdResolvedConfiguration(self, run_as_root, password=None) -> bool:
        """ Save the systemd-resolved configuration in a file.
        Copies the content of the configuration file to a temporary file,
        replacing the changed values. After that, the temporary file
        is copied to the configuration file; this requires root privileges.
        """
        tmp_fn = '/tmp/resolv.conf'

        if run_as_root: assert(password)

        print("DNSConfigurationModel.save")
        try:
            with open(self.__conf_fn, 'r') as f_in:
                with open(tmp_fn, 'w') as f_out:
                    updated_vars = set()
                    for line in f_in:
                        m = re.match('^([A-Za-z]+)=', line)
                        if m:
                            var = m.group(1)
                            if var in self.__systemdResolvedParams:
                                f_out.write(
                                      "{}={}\n".format(var, self.__systemdResolvedParams[var]))
                                updated_vars.add(var)
                            else:
                                f_out.write(line)
                        else:
                            f_out.write(line)
                    # resolved.conf might not define all
                    for var in self.__systemdResolvedParams:
                        if not var in updated_vars:
                            if verbose: print("Missing:", var)
                            f_out.write(
                                      "{}={}\n".format(var,
                                                       self.__systemdResolvedParams[var]))
            if run_as_root:
                x = DNSConfigurationModel.runShellCommandAsRoot(password, 'cp', tmp_fn, self.__conf_fn)
                if x:
                    msg = "Could not update '{}'; copy process terminated with {}".format(self.__conf_fn, x)
                    QMessageBox.critical(None, "Error", msg)
                return x == 0

            else:
                s = os.system('cp ' + tmp_fn + ' ' + self.__conf_fn)
                return s == 0

        except IOError as e:
            print("Cannot open", e)
            return False


    def __startStopResolvers(self, password):
        if not self.__resolver == self.__resolver0:
            print("Starting systemctl ...")
            if self.__resolver == SystemCtl.SVC_SYSTEMD_RESOLVED:
                s = SystemCtl.startOrStop('stop', SystemCtl.SVC_PORTMASTER, password)
                if not s: return False
                s = SystemCtl.startOrStop('start', SystemCtl.SVC_SYSTEMD_RESOLVED, password)
                if not s: return False
            elif self.__resolver == SystemCtl.SVC_PORTMASTER:
                s = SystemCtl.startOrStop('stop', SystemCtl.SVC_SYSTEMD_RESOLVED, password)
                if not s: return False
                s = SystemCtl.startOrStop('start', SystemCtl.SVC_PORTMASTER, password)
                if not s: return False
            print("... finished")
        return True


    def save(self, conf_fn, run_as_root, password=None):
        """ Save modified parameters to the configuration file and stop/start DNS
        resolvers as specified. """
        # FIXME: Check error status. The savexxx methods already show message
        # boxes on error.
        if self.__systemdResolvedParams != self.__systemdResolvedParams0:
            s = self.__saveSysdResolvedConfiguration(run_as_root, password)
            assert(s in (True, False))
            if s and self.__resolver == SystemCtl.SVC_SYSTEMD_RESOLVED:
                s = SystemCtl.startOrStop('restart', SystemCtl.SVC_SYSTEMD_RESOLVED, password)
                assert(s in (True, False))
                if s:
                    self.__systemdResolvedParams0 = self.__systemdResolvedParams.copy()

        if self.__resolver != self.__resolver0:
            s = self.__startStopResolvers(password)
            assert(s in (True, False))
            if s:
                self.__resolver0 = self.__resolver

        # To be on the safe side read the services status:
        if SystemCtl.status(SystemCtl.SVC_SYSTEMD_RESOLVED) == 0:
            self.__resolver = SystemCtl.SVC_SYSTEMD_RESOLVED
        elif SystemCtl.status(SystemCtl.SVC_PORTMASTER) == 0:
            self.__resolver = SystemCtl.SVC_PORTMASTER
        else:
            self.__resolver = None


    def save_unused(self, conf_fn, run_as_root, password=None):
        """ Save the changed data to the configuration file.

        Copies the content of the configuration file to a temporary file,
        replacing the changed values. After that, the temporary file
        is copied to the configuration file; this requires root privileges.
        """
        tmp_fn = '/tmp/resolv.conf'

        if run_as_root: assert(password)

        print("DNSConfigurationModel.save")
        try:
            with open(conf_fn, 'r') as f_in:
                with open(tmp_fn, 'w') as f_out:
                    updated_vars = set()
                    for line in f_in:
                        m = re.match('^([A-Za-z]+)=', line)
                        if m:
                            var = m.group(1)
                            if var in self.__systemdResolvedParams:
                                f_out.write(
                                      "{}={}\n".format(var, self.__systemdResolvedParams[var]))
                                updated_vars.add(var)
                            else:
                                f_out.write(line)
                        else:
                            f_out.write(line)
                    # resolved.conf might not define all
                    for var in self.__systemdResolvedParams:
                        if not var in updated_vars:
                            if verbose: print("Missing:", var)
                            f_out.write(
                                      "{}={}\n".format(var,
                                                       self.__systemdResolvedParams[var]))
            if run_as_root:
                x = DNSConfigurationModel.runShellCommandAsRoot(password, 'cp', tmp_fn, conf_fn)
                if x:
                    msg = "Could not update '{}'; copy process terminated with {}".format(conf_fn, x)
                    QMessageBox.critical(None, "Error", msg)

            else:
                #os.copy(tmp_fn, conf_fn)
                os.system('cp ' + tmp_fn + ' ' + conf_fn)

        except IOError as e:
            print("Cannot open", e)

        if not self.__resolver == self.__resolver0:
            print("Starting systemctl ...")
            if self.__resolver == SystemCtl.SVC_SYSTEMD_RESOLVED:
                SystemCtl.startOrStop('stop', SystemCtl.SVC_PORTMASTER, password)
                SystemCtl.startOrStop('start', SystemCtl.SVC_SYSTEMD_RESOLVED, password)
            elif self.__resolver == SystemCtl.SVC_PORTMASTER:
                SystemCtl.startOrStop('stop', SystemCtl.SVC_SYSTEMD_RESOLVED, password)
                SystemCtl.startOrStop('start', SystemCtl.SVC_PORTMASTER, password)
            print(".. finished")

        # To be on the safe side read the services status:
        if SystemCtl.status(SystemCtl.SVC_SYSTEMD_RESOLVED) == 0:
            self.__resolver = SystemCtl.SVC_SYSTEMD_RESOLVED
        elif SystemCtl.status(SystemCtl.SVC_PORTMASTER) == 0:
            self.__resolver = SystemCtl.SVC_PORTMASTER
        else:
            self.__resolver = None

        # Values saved, set status to 'not modified'
        self.__resolver0 = self.__resolver
        self.__systemdResolvedParams0 = self.__systemdResolvedParams.copy()


    def isModified(self):
        """ Check if the model is modified. """
        print("DNSConfigurationModel.isModified")
        print('resolver0 =', self.__resolver0, 'resolver =', self.__resolver)
        return not (self.__resolver == self.__resolver0 and self.__systemdResolvedParams == self.__systemdResolvedParams0)


    def resolver(self):
        """ Returns the name of the current resolver. May be None."""
        return self.__resolver


    def setResolver(self, resolver):
        """ Sets the currently active resolver."""
        assert(resolver in (SystemCtl.SVC_SYSTEMD_RESOLVED, SystemCtl.SVC_PORTMASTER))
        self.__resolver = resolver


    def getSystemdResolvedParameter(self, key):
        """ Return the parameter getSystemdResolvedParameter of associated with 'key'. """
        if key in self.__systemdResolvedParams:
            return self.__systemdResolvedParams[key]
        else:
            return None


    def setResolvedParameter(self, key, value):
        """ Set the parameter getSystemdResolvedParameter of associated with 'key'. """
        self.__systemdResolvedParams[key] = value


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


class DNSselector():
    """
    Displays a combobox and an entry field side-by-side.

    The combobox allows for selecting a DNS provider (such as Google or Quad9)
    or manually entering an IPv4 address in dotted notation.
    """
    def __init__(self, view, model, layout, row, text, values, key):

        assert(type(view) == DNSConfigurationrView)
        self.__view = view
        assert(type(model) == DNSConfigurationModel)
        self.__model = model
        assert(type(key) == str)
        self.__key = key
        assert(type(values) == list)
        self.__values = values

        ip = model.getSystemdResolvedParameter(key)
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
        self.__value_combo.setCurrentText(self.__model.getSystemdResolvedParameter(key))
        self.__value_combo.currentIndexChanged.connect(self.__onValueChanged)


    def __onValueChanged(self, index):
        print("EnumSelector.updateButtonStatus:", self.__key, self.__values[index], index)
        self.__model.setResolvedParameter(self.__key, self.__values[index])
        self.__view.updateButtonStatus()


class DNSConfigurationrView(QMainWindow):
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
        super(DNSConfigurationrView, self).__init__()

        self.__run_as_root = run_as_root
        self.__config_fn = config_fn
        self.__model = model
        self.__password = None

        self.__createWidgets(model)
        self.updateButtonStatus()             # Convenient way to set button status


    def updateButtonStatus(self):
        """ Update 'apply' and 'close buttens according to the state of
        the model.

        Widgets should call this methon after each user interaction.
        """
        m = self.__model.isModified()
        if verbose: print("Value of some widget has changed!", m)
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
        resolver = self.__model.resolver()
        self.__sysd_group.setChecked(resolver == SystemCtl.SVC_SYSTEMD_RESOLVED)
        self.__portmaster.setChecked(resolver == SystemCtl.SVC_PORTMASTER)


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
                    self.__model.save(self.__config_fn, self.__run_as_root, self.__password)
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
        """ Called when the user toggle the 'systemd-resolved' check mark."""
        print("Systemd resolver clicked: ", check_state)
        if check_state:
            self.__portmaster.setChecked(False)
            self.__model.setResolver(SystemCtl.SVC_SYSTEMD_RESOLVED)
            self.updateButtonStatus()


    def __onPortmasterToggled(self, checkState):
        """ Called when the user toggle the 'portmaster' check mark."""
        #checkState = self.__portmaster.checkState()
        print("Portmaster clicked:", checkState)
        if checkState:
            self.__sysd_group.setChecked(False)
            self.__model.setResolver(SystemCtl.SVC_PORTMASTER)
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
                        DNSConfigurationrView.DNSproviders, 'DNS')

        row = row + 1
        self.__DNSFallback = DNSselector(self, model, sysd_grid, row,
                                         'Fallback DNS server',
                                         DNSConfigurationrView.DNSproviders,
                                         'FallbackDNS')

        row = row + 1
        self.__DoT= EnumSelector(self, model, sysd_grid, row, 'DNS over TLS',
                                 ['no', 'yes', 'opportunistic'],
                                 'DNSOverTLS')

        row = row + 1
        self.__DNSSEC = EnumSelector(self, model, sysd_grid, row, 'DNSSEC',
                                     ['no', 'yes', 'allow-downgrade'],
                                     'DNSSEC',)

        self.__sysd_group = QGroupBox("Systemd-resolved", widget)
        self.__sysd_group.setCheckable(True)
        if model.resolver() == SystemCtl.SVC_SYSTEMD_RESOLVED:
            self.__sysd_group.setChecked(True)
        else:
            self.__sysd_group.setChecked(False)
        self.__sysd_group.toggled.connect(self.__onSystemdResolverToggled)
        self.__sysd_group.setLayout(sysd_grid)
        main_layout.addWidget(self.__sysd_group)

        self.__portmaster = QGroupBox("Portmaster", widget)
        self.__portmaster.setCheckable(True)
        if model.resolver() == SystemCtl.SVC_PORTMASTER:
            self.__portmaster.setChecked(True)
        else:
            self.__portmaster.setChecked(False)
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

    model = DNSConfigurationModel(args.config)
    app = QApplication(sys.argv)
    root_window = DNSConfigurationrView(model, config_fn=args.config,
                                run_as_root=not args.no_root)
    root_window.show()
    app.exec_()
