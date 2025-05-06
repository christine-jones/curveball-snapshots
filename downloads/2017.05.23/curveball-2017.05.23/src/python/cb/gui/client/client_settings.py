#!/usr/bin/env python
#
# This material is based upon work supported by the Defense Advanced
# Research Projects Agency under Contract No. N66001-11-C-4017.
#
# Copyright 2014 - Raytheon BBN Technologies Corp.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.  See the License for the specific language governing
# permissions and limitations under the License.

import sys
import os

from PySide import QtGui, QtCore, QtUiTools
import cb.util.platform

dirname = os.path.normpath(
    os.path.abspath(os.path.dirname(sys.argv[0]) or '.'))

# set the paths for curveball client executables
client = os.path.normpath(os.path.join(dirname, "client"))
clientKeyConfig = os.path.normpath(os.path.join(dirname, "client-key-config"))
# if running from windows, launch .exe
if cb.util.platform.PLATFORM == 'win32':
    client += ".exe"
else:
    client += ".py"
print client

class CurveballClientSettings(QtGui.QFrame):
    def __init__(self, settings, parent=None):
        super(CurveballClientSettings, self).__init__(parent)
        self.name = "Curveball Client Settings"
        self.qSettings = settings
        self.keyChanged = False
        self.keyLoadProcess = None
        self.keyLoadProcessOutput = []
        self.keyConfigProcess = None
        self.keyConfigProcessOutput = []

        # Initialize default options auto complete lists
        self.optModeProxy = "SOCKS Proxy"
        self.optModeVpn = "VPN"
        self.modeOptsList = [self.optModeProxy, self.optModeVpn]
        self.optTunnelHttp = "HTTP"
        self.optTunnelUniHttp = "Unidirectional HTTP"
        self.optTunnelTls = "TLS"
        self.optTunnelUniTls = "Unidirectional TLS"
        self.tunnelOptsList = [self.optTunnelHttp, 
                self.optTunnelUniHttp, 
                self.optTunnelTls, 
                self.optTunnelUniTls]
        self.hostAutoCompleteList = ["hotel.nct.bbn.com"]
        self.portAutoCompleteList = ["5010"]
        self.subnetAutoCompleteList = ["0/1,128/1"]
        self.optKeyFile = os.path.normpath(
                os.path.join(dirname, '..', 'auth', 'master.km'))
        self.optKey = "cbtest0"
        self.keyOptsList = [self.optKey]

        # Load saved settings
        self.readSettings()
        
        # Initialize the UI
        self.initUi()

        # Set actions for all UI events
        self.modeComboBox.currentIndexChanged.connect(self.onInputChange)
        self.hostLineEdit.editingFinished.connect(self.onInputChange)
        self.tunnelComboBox.currentIndexChanged.connect(self.onInputChange)
        self.portLineEdit.editingFinished.connect(self.onInputChange)
        self.subnetLineEdit.editingFinished.connect(self.onInputChange)
        self.keyFileButton.clicked.connect(self.onButtonClick)
        self.keySelectComboBox.currentIndexChanged.connect(self.onInputChange)

        # Final formatting
        self.setWindowTitle(self.name)

    def getCurveballArguments(self):
        currSettings = []
        currDetails = ""
        currSettings.append(client)
        currSettings.append('-d')
        host = self.currHost
        tunnel = []

        if self.currTunnel == self.optTunnelHttp:
            host += ':80'
            tunnel.append('-w')
        elif self.currTunnel == self.optTunnelUniHttp:
            host += ':80'
            tunnel.append('-w')
            tunnel.append('-u')
        elif self.currTunnel == self.optTunnelTls:
            host += ':443'
        elif self.currTunnel == self.optTunnelUniTls:
            host += ':443'
            tunnel.append('-u')

        currSettings.append(host)
        for i in range(len(tunnel)):
            currSettings.append(tunnel[i])

        if self.currMode == self.optModeProxy:
            currSettings.append('-p')
            currSettings.append(self.currPort)
            currDetails = "Configure your SOCKS proxy to %s" % os.linesep
            currDetails += "Host: 127.0.0.1 %s" % os.linesep
            currDetails += "Port: %s" % self.currPort
        elif self.currMode == self.optModeVpn:
            currSettings.append('-v')
            currSettings.append('-c')
            currSettings.append(self.currSubnet)
            currDetails = "VPN Subnet: %s" % self.currSubnet

        currSettings.append('-x') # use real keys

        # save current settings
        self.writeSettings()        
        # load new key if changed
        if self.keyChanged:
            self.launchKeyConfigProcess()
            self.keyChanged = False
        
        return currSettings, currDetails

    def toggleUiEnabled(self, enable):
        if enable:
            for uiElement in self.uiElements:
                uiElement.setEnabled(True)
        else:
            for uiElement in self.uiElements:
                uiElement.setDisabled(True)

    def closeEvent(self, event):
        self.writeSettings()
        return super(CurveballClientSettings, self).closeEvent(event)

    def processDownEvent(self, exitCode):
        sender = self.sender()
        if sender is self.keyLoadProcess:
            if exitCode == 0 and len(self.keyLoadProcessOutput) > 0:
                # parse keys from output
                output = ''.join(self.keyLoadProcessOutput)
                lines = output.split(os.linesep)
                if lines[0] == "Available knames:":
                    self.keyOptsList[:] = [] # clear old keys from list
                    keys = lines[1].split(" ")
                    for key in keys:
                        self.keyOptsList.append(key)

                    if len(self.keyOptsList) <= 0:
                        self.currKey = "---"
                        self.keyOptsList.add(self.currKey)

                    self.keySelectComboBox.clear()
                    self.keySelectComboBox.addItems(self.keyOptsList)
                    self.keyLoadProcessOutput[:] = []
        elif sender is self.keyConfigProcess and exitCode == 0:
            self.keyConfigured = self.currKey
            print "Curveball now configured to run with key %s" % self.currKey

    def processOutputReadyEvent(self):
        sender = self.sender()
        # Read standard error
        processError = str(sender.readAllStandardError()).strip()
        if processError:
            print processError
        # Read standard output
        processOutput = str(sender.readAllStandardOutput()).strip()
        if processOutput:
            print processOutput
            if sender is self.keyLoadProcess:
                self.keyLoadProcessOutput.append(processOutput)
            elif sender is self.keyConfigProcess:
                self.keyConfigProcessOutput.append(processOutput)
      
    def launchKeyConfigProcess(self):
        args = []
        args.append(clientKeyConfig)
        args.append('-c')
        args.append('-m')
        args.append(self.currKeyFile)
        args.append(self.currKey)
        self.keyConfigProcess = self.launchProcess(self.keyConfigProcess, args)
        self.keyConfigProcess.waitForFinished()

    def launchKeyLoadProcess(self):
        args = []
        args.append(clientKeyConfig)
        args.append('-m')
        args.append(self.currKeyFile)
        args.append('-a')
        self.keyLoadProcess = self.launchProcess(self.keyLoadProcess, args)

    def launchProcess(self, process, args):
        if process is None:
            process = QtCore.QProcess()
        else:
            # If process is not None, it means
            # that it has been run before. Cleanup from previous run.
            process.readyRead.disconnect(
                    self.processOutputReadyEvent)
            process.finished.disconnect(self.processDownEvent)

        # Connect callback signals
        process.readyRead.connect(self.processOutputReadyEvent)
        process.finished.connect(self.processDownEvent)
        process.start(args[0], args[1:])
        return process

    def onButtonClick(self):
        sender = self.sender()
        if sender is self.keyFileButton:
            fileName,_ = QtGui.QFileDialog.getOpenFileName(self,
                "Select Key File", self.currKeyFile, 
                "Key Files (*.km);; All Files (*)")
            
            if not fileName:
                return
                
            self.currKeyFile = fileName
            self.keyFileButton.setText(self.currKeyFile)
            self.launchKeyLoadProcess()

    def onInputChange(self):
        # Save current input
        # Triggered on change to input element
        sender = self.sender()
        if sender is self.modeComboBox:
            self.currMode = self.modeOptsList[self.modeComboBox.currentIndex()]
        elif sender is self.hostLineEdit:
            self.currHost = self.hostLineEdit.text()
            if self.currHost in self.hostAutoCompleteList:
                self.hostAutoCompleteList.remove(self.currHost)
            self.hostAutoCompleteList.append(self.currHost)
            hostCompleter = QtGui.QCompleter(
                    self.hostAutoCompleteList, self)
            self.hostLineEdit.setCompleter(hostCompleter)
        elif sender is self.tunnelComboBox:
            self.currTunnel = self.tunnelOptsList[
                    self.tunnelComboBox.currentIndex()]
        elif sender is self.portLineEdit:
            self.currPort = self.portLineEdit.text()
            if self.currPort in self.portAutoCompleteList:
                self.portAutoCompleteList.remove(self.currPort)
            self.portAutoCompleteList.append(self.currPort)
            portCompleter = QtGui.QCompleter(
                    self.portAutoCompleteList, self)
            self.portLineEdit.setCompleter(portCompleter)
        elif sender is self.subnetLineEdit:
            self.currSubnet = self.subnetLineEdit.text()
            if self.currSubnet in self.subnetAutoCompleteList:
                self.subnetAutoCompleteList.remove(self.currSubnet)
            self.subnetAutoCompleteList.append(self.currSubnet)
            subnetCompleter = QtGui.QCompleter(
                    self.subnetAutoCompleteList, self)
            self.subnetLineEdit.setCompleter(subnetCompleter)
        elif sender is self.keySelectComboBox:
            self.keyChanged = True
            self.currKey = self.keyOptsList[
                    self.keySelectComboBox.currentIndex()]

    def readSettings(self):
        # Initialize names used for settings
        self.cbMode = "cbMode"
        self.cbHost = "cbHost"
        self.cbHostArray = "cbHostArray"
        self.cbTunnel = "cbTunnel"
        self.cbPort = "cbPort"
        self.cbPortArray = "cbPortArray"
        self.cbSubnet = "cbSubnet"
        self.cbSubnetArray = "cbSubnetArray"
        self.cbKeyFile = "cbKeyFile"
        self.cbKey = "cbKey"
        self.cbKeyArray = "cbKeyArray"
        self.cbKeyConfigured = "cbKeyConfigured"

        # mode
        self.currMode = self.qSettings.value(self.cbMode, self.modeOptsList[0])
        # host
        size = self.qSettings.beginReadArray(self.cbHostArray)
        for i in range(size):
            self.qSettings.setArrayIndex(i)
            self.currHost = self.qSettings.value(self.cbHost, 
                    self.hostAutoCompleteList[0])
            if self.currHost in self.hostAutoCompleteList:
                self.hostAutoCompleteList.remove(self.currHost)
            self.hostAutoCompleteList.append(self.currHost)
        self.qSettings.endArray()
        self.currHost = self.hostAutoCompleteList[-1]
        # tunnel
        self.currTunnel = self.qSettings.value(self.cbTunnel, 
                self.tunnelOptsList[0])
        # port
        size = self.qSettings.beginReadArray(self.cbPortArray)
        for i in range(size):
            self.qSettings.setArrayIndex(i)
            self.currPort = self.qSettings.value(self.cbPort,
                    self.portAutoCompleteList[0])
            if self.currPort in self.portAutoCompleteList:
                self.portAutoCompleteList.remove(self.currPort)
            self.portAutoCompleteList.append(self.currPort)
        self.qSettings.endArray()
        self.currPort = self.portAutoCompleteList[-1]
        # subnet
        size = self.qSettings.beginReadArray(self.cbSubnetArray)
        for i in range(size):
            self.qSettings.setArrayIndex(i)
            self.currSubnet = self.qSettings.value(self.cbSubnet,
                    self.subnetAutoCompleteList[0])
            if self.currSubnet in self.subnetAutoCompleteList:
                self.subnetAutoCompleteList.remove(self.currSubnet)
            self.subnetAutoCompleteList.append(self.currSubnet)
        self.qSettings.endArray()
        self.currSubnet = self.subnetAutoCompleteList[-1]
        # key file
        self.currKeyFile = self.qSettings.value(self.cbKeyFile,
                self.optKeyFile)
        # key
        size = self.qSettings.beginReadArray(self.cbKeyArray)
        if size > 0: # if saved keys available, clear default
            self.keyOptsList[:] = []
        for i in range(size):
            self.qSettings.setArrayIndex(i)
            self.currKey = self.qSettings.value(self.cbKey,
                    self.optKey)
            if self.currKey in self.keyOptsList:
                self.keyOptsList.remove(self.currKey)
            self.keyOptsList.append(self.currKey)
        self.qSettings.endArray()
        self.currKey = self.keyOptsList[0]
        # currently configured key
        self.keyConfigured = self.qSettings.value(self.cbKeyConfigured, None)
        if self.keyConfigured is not None:
            self.currKey = self.keyConfigured

    def writeSettings(self):
        # Write current values to persistent settings
        # mode
        self.qSettings.setValue(self.cbMode, self.currMode)
        # host
        self.qSettings.beginWriteArray(self.cbHostArray)
        for i in range(len(self.hostAutoCompleteList)):
            self.qSettings.setArrayIndex(i)
            self.qSettings.setValue(self.cbHost, self.hostAutoCompleteList[i])
        self.qSettings.endArray()
        # tunnel
        self.qSettings.setValue(self.cbTunnel, self.currTunnel)
        # port
        self.qSettings.beginWriteArray(self.cbPortArray)
        for i in range(len(self.portAutoCompleteList)):
            self.qSettings.setArrayIndex(i)
            self.qSettings.setValue(self.cbPort, self.portAutoCompleteList[i])
        self.qSettings.endArray()
        # subnet
        self.qSettings.beginWriteArray(self.cbSubnetArray)
        for i in range(len(self.subnetAutoCompleteList)):
            self.qSettings.setArrayIndex(i)
            self.qSettings.setValue(
                    self.cbSubnet, self.subnetAutoCompleteList[i])
        self.qSettings.endArray()
        # key file
        self.qSettings.setValue(self.cbKeyFile, self.currKeyFile)
        # key
        self.qSettings.beginWriteArray(self.cbKeyArray)
        for i in range(len(self.keyOptsList)):
            self.qSettings.setArrayIndex(i)
            self.qSettings.setValue(
                    self.cbKey, self.keyOptsList[i])
        self.qSettings.endArray()
        if self.keyConfigured is not None:
            self.qSettings.setValue(self.cbKeyConfigured, self.keyConfigured)

    def initUi(self):
        # Initialize all UI elements
        self.uiElements = [] # easily iterate over elements to en/disable
        
        modeLabel = QtGui.QLabel("Mode:")
        self.modeComboBox = QtGui.QComboBox()
        self.modeComboBox.addItems(self.modeOptsList)
        modeLabel.setBuddy(self.modeComboBox)
        self.uiElements.append(self.modeComboBox)

        hostLabel = QtGui.QLabel("Decoy Host:")
        self.hostLineEdit = QtGui.QLineEdit()
        hostCompleter = QtGui.QCompleter(self.hostAutoCompleteList, self)
        self.hostLineEdit.setCompleter(hostCompleter)
        self.hostLineEdit.setText(self.hostAutoCompleteList[0])
        hostLabel.setBuddy(self.hostLineEdit)
        self.uiElements.append(self.hostLineEdit)

        tunnelLabel = QtGui.QLabel("Curveball Tunnel:")
        self.tunnelComboBox = QtGui.QComboBox()
        self.tunnelComboBox.addItems(self.tunnelOptsList)
        tunnelLabel.setBuddy(self.tunnelComboBox) 
        self.uiElements.append(self.tunnelComboBox)

        proxyOptsLabel = QtGui.QLabel("Proxy Options")
        portLabel = QtGui.QLabel("SOCKS Port:")
        self.portLineEdit = QtGui.QLineEdit()
        portCompleter = QtGui.QCompleter(self.portAutoCompleteList, self)
        self.portLineEdit.setCompleter(portCompleter)
        self.portLineEdit.setText(self.portAutoCompleteList[0])
        portLabel.setBuddy(self.portLineEdit)
        self.uiElements.append(self.portLineEdit)

        vpnOptsLabel = QtGui.QLabel("VPN Options")
        subnetLabel = QtGui.QLabel("Subnets:")
        self.subnetLineEdit = QtGui.QLineEdit()
        subnetCompleter = QtGui.QCompleter(
                self.subnetAutoCompleteList, self)
        self.subnetLineEdit.setCompleter(subnetCompleter)
        self.subnetLineEdit.setText(self.subnetAutoCompleteList[0])
        subnetLabel.setBuddy(self.subnetLineEdit)
        self.uiElements.append(self.subnetLineEdit)

        keyFileLabel = QtGui.QLabel("Select Key File:")
        self.keyFileButton = QtGui.QToolButton()
        self.keyFileButton.setMinimumWidth(250)
        self.keyFileButton.setSizePolicy(QtGui.QSizePolicy.Preferred,
                QtGui.QSizePolicy.Fixed)
        keyFileLabel.setBuddy(self.keyFileButton)
        self.uiElements.append(self.keyFileButton)

        keySelectLabel = QtGui.QLabel("Select Key:")
        self.keySelectComboBox = QtGui.QComboBox()
        self.keySelectComboBox.addItems(self.keyOptsList)
        keySelectLabel.setBuddy(self.keySelectComboBox)
        self.uiElements.append(self.keySelectComboBox)

        # Load views with saved settings
        if self.currMode in self.modeOptsList:
            self.modeComboBox.setCurrentIndex(
                    self.modeOptsList.index(self.currMode))
        self.hostLineEdit.setText(self.currHost)
        if self.currTunnel in self.tunnelOptsList:
            self.tunnelComboBox.setCurrentIndex(
                        self.tunnelOptsList.index(self.currTunnel))
        self.portLineEdit.setText(self.currPort)
        self.subnetLineEdit.setText(self.currSubnet)
        self.keyFileButton.setText(self.currKeyFile)
        if self.currKey in self.keyOptsList:
            self.keySelectComboBox.setCurrentIndex(
                    self.keyOptsList.index(self.currKey))

        horizontalSpacer = QtGui.QSpacerItem(
                40, 20, QtGui.QSizePolicy.Expanding, QtGui.QSizePolicy.Minimum)
        
        # Add all UI elements to layout
        mainLayout = QtGui.QGridLayout()
        mainLayout.addWidget(modeLabel, 0, 0)
        mainLayout.addItem(horizontalSpacer, 0, 1)
        mainLayout.addWidget(self.modeComboBox, 0, 2)
        mainLayout.addWidget(hostLabel, 1, 0)
        mainLayout.addWidget(self.hostLineEdit, 1, 2)
        mainLayout.addWidget(tunnelLabel, 2, 0)
        mainLayout.addWidget(self.tunnelComboBox, 2, 2)
        mainLayout.addWidget(portLabel, 3, 0)
        mainLayout.addWidget(self.portLineEdit, 3, 2)
        mainLayout.addWidget(subnetLabel, 4, 0)
        mainLayout.addWidget(self.subnetLineEdit, 4, 2)
        mainLayout.addWidget(keyFileLabel, 5, 0)
        mainLayout.addWidget(self.keyFileButton, 5, 2)
        mainLayout.addWidget(keySelectLabel, 6, 0)
        mainLayout.addWidget(self.keySelectComboBox, 6, 2)
        mainLayout.setColumnMinimumWidth(1, 40)
        mainLayout.setColumnMinimumWidth(2, 60)
        mainLayout.setColumnStretch(2, 1)
        self.setLayout(mainLayout)

def init():
    app = QtGui.QApplication(sys.argv)
    qSettings = QtCore.QSettings("BBN", "Curveball Client Settings")
    dirname = os.path.normpath(
            os.path.abspath(os.path.dirname(sys.argv[0]) or '.'))
    settings = CurveballClientSettings(qSettings, dirname)
    settings.show()
    sys.exit(app.exec_())

if __name__ == '__main__':
    init()
