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

import client_settings
import res_rc

from PySide import QtGui, QtCore, QtUiTools

class CurveballClientMain(QtGui.QFrame):
    STATE_STOPPED  = 0
    STATE_STARTING = 1
    STATE_STARTED  = 2

    def __init__(self, qSettings, curveballClientSettings, parent=None):
        super(CurveballClientMain, self).__init__(parent)

        self.name = "Curveball Client"
        self.qSettings = qSettings
        self.curveballClientSettings = curveballClientSettings

        self.clientProcess = None
        self.mainButtonClicked = False 
        self.state = CurveballClientMain.STATE_STOPPED
        self.details = ""

        # Load saved settings
        self.readSettings()

        # Initialize the UI
        self.initUi()

        # Set actions for all UI events
        self.mainButton.clicked.connect(self.onMainButtonClick)

        # Final formatting
        self.setWindowTitle(self.name)

    def closeEvent(self, event):
        self.writeSettings()
        if self.clientProcess is not None:
            if self.clientProcess.state() is not QtCore.QProcess.ProcessState.NotRunning:
                self.clientProcess.kill()
                self.clientProcess.waitForFinished()
        return super(CurveballClientMain, self).closeEvent(event)

    def processDownEvent(self, exitCode):
        self.toggleState(CurveballClientMain.STATE_STOPPED)

    def processOutputReadyEvent(self):
        processOutput = str(self.clientProcess.readAllStandardOutput())
        processError = str(self.clientProcess.readAllStandardError())
        print processError
        print processOutput
        # Check output for curveball tunnel-up callback string from client.py
        if "Curveball ready" in processOutput:
            self.toggleState(CurveballClientMain.STATE_STARTED)

    def launchCurveballClientProcess(self, args):
        if self.clientProcess is None:
            self.clientProcess = QtCore.QProcess()
        else:
            # If self.clientProcess is not None, it means 
            # it has been run before. So, cleanup from previous run.
            self.clientProcess.readyRead.disconnect(
                    self.processOutputReadyEvent)
            self.clientProcess.finished.disconnect(self.processDownEvent)

        # Connect callback signals
        self.clientProcess.readyRead.connect(self.processOutputReadyEvent)
        self.clientProcess.finished.connect(self.processDownEvent)
        # Start client process with args from CurveballClientSettings
        self.clientProcess.start(args[0], args[1:])

    def onMainButtonClick(self):
        self.mainButtonClicked = True
        if self.state is CurveballClientMain.STATE_STOPPED:
            self.toggleState(CurveballClientMain.STATE_STARTING)
            # Configure with saved settings and start client.py
            args, self.details = self.curveballClientSettings.getCurveballArguments()
            self.launchCurveballClientProcess(args)
        elif (self.state is CurveballClientMain.STATE_STARTED) or (self.state is CurveballClientMain.STATE_STARTING):
            # If client subprocess is running, stop it
            if self.clientProcess is not None and self.clientProcess.state() is not QtCore.QProcess.ProcessState.NotRunning:
                self.clientProcess.kill()

    def toggleState(self, newState):
        self.state = newState
        if self.state is CurveballClientMain.STATE_STOPPED:
            self.mainButton.setImage(':/curveball/res/button_off.png')
            # If button clicked state = STOPPED
            if self.mainButtonClicked:
                # Blank text instead of visible=False to maitain layout spacing
                self.detailsLabel.setText("")
                self.detailsLabel.setVisible(True)
                self.detailsImage.setVisible(False)
            # Else, state = FAILED
            else:
                self.detailsLabel.setText("Curveball failed! Please check that you have a valid network connection and try again.")
                self.detailsLabel.setVisible(True)
                self.detailsImage.setVisible(True)
            self.curveballClientSettings.toggleUiEnabled(True)
        elif self.state is CurveballClientMain.STATE_STARTING:
            self.mainButton.setImage(':/curveball/res/button_starting.png')
            self.detailsLabel.setText("Starting Curveball...")
            self.detailsLabel.setVisible(True)
            self.detailsImage.setVisible(False)
            self.curveballClientSettings.toggleUiEnabled(False)
        elif self.state is CurveballClientMain.STATE_STARTED:
            self.mainButton.setImage(':/curveball/res/button_on.png')
            self.detailsLabel.setText(self.details)
            self.detailsLabel.setVisible(True)
            self.detailsImage.setVisible(False)
        
        self.mainButtonClicked = False

    def readSettings(self):
        self.cbSize = "size"
        self.cbPos = "pos"
        self.resize(
                self.qSettings.value(self.cbSize, QtCore.QSize(400, 400)))
        self.move(
                self.qSettings.value(self.cbPos, QtCore.QPoint(200, 200)))

    def writeSettings(self):
        self.qSettings.setValue(self.cbSize, self.size())
        self.qSettings.setValue(self.cbPos, self.pos())

    def initUi(self):
        self.mainButton = ImageButton(':/curveball/res/button_off.png')
        self.detailsLabel = QtGui.QLabel()
        self.detailsLabel.setWordWrap(True)
        self.detailsLabel.setFixedHeight(100) # Prevents shift in layout
        self.detailsImage = QtGui.QLabel()
        self.detailsImage.setPixmap(':/curveball/res/icon_warning.png')

        mainLayout = QtGui.QVBoxLayout()
        mainLayout.addItem(QtGui.QSpacerItem(
            20, 20, QtGui.QSizePolicy.Expanding, QtGui.QSizePolicy.Minimum))
        mainLayout.addWidget(self.mainButton)
        detailsLayout = QtGui.QHBoxLayout()
        detailsLayout.addItem(QtGui.QSpacerItem(
            40, 20, QtGui.QSizePolicy.Expanding, QtGui.QSizePolicy.Minimum))
        detailsLayout.addWidget(self.detailsImage)
        detailsLayout.addWidget(self.detailsLabel)
        detailsLayout.addItem(QtGui.QSpacerItem(
            40, 20, QtGui.QSizePolicy.Expanding, QtGui.QSizePolicy.Minimum))
        mainLayout.addItem(QtGui.QSpacerItem(
            20, 10, QtGui.QSizePolicy.Expanding, QtGui.QSizePolicy.Minimum))
        mainLayout.addLayout(detailsLayout)
        mainLayout.addItem(QtGui.QSpacerItem(
            20, 10, QtGui.QSizePolicy.Expanding, QtGui.QSizePolicy.Minimum))
        self.setLayout(mainLayout)

        # Final style adjustments
        self.detailsImage.setVisible(False)
        self.setFrameStyle(QtGui.QFrame.Panel | QtGui.QFrame.Raised)
        self.setLineWidth(2)
        self.setStyleSheet(
                "background-image: url(:/curveball/res/bckgnd_main.png);")

class ImageButton(QtGui.QLabel):
    clicked = QtCore.Signal()

    def __init__(self, pixmap, parent=None):
        super(ImageButton, self).__init__(parent)
        self.setScaledContents(False)
        self.setAlignment(QtCore.Qt.AlignCenter)

        self.setImage(pixmap)

    def setImage(self, pixmap):
        self.setPixmap(pixmap)

    def mousePressEvent(self, event):
        self.clicked.emit()

def init():
    app = QtGui.QApplication(sys.argv)
    qSettings = QtCore.QSettings("BBN", "Curveball Client")
    curveballClientSettings = client_settings.CurveballClientSettings(qSettings)
    curveballClientMain = CurveballClientMain(
            qSettings, 
            curveballClientSettings)
    curveballClientMain.show()
    sys.exit(app.exec_())

if __name__ == '__main__':
    init()

