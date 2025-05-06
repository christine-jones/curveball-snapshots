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
from cb.gui.client.client_settings import CurveballClientSettings
from cb.gui.client.client_main import CurveballClientMain

class MainWindow(QtGui.QMainWindow):

    def __init__(self):
        super(MainWindow, self).__init__()

        self.qSettings = QtCore.QSettings("BBN", "BBN Cuveball")

        self.readSettings()
        self.createActions()
        self.createMenus()
        self.createStatusBar()

        # Initialize CurveballClientSettings widget
        dock = QtGui.QDockWidget("Curveball Client Settings", self)
        dock.setAllowedAreas(
                QtCore.Qt.LeftDockWidgetArea | QtCore.Qt.RightDockWidgetArea | QtCore.Qt.TopDockWidgetArea)
        self.curveballClientSettings = CurveballClientSettings(
                self.qSettings, dock)
        dock.setWidget(self.curveballClientSettings)

        # Initialize CurveballClient widget
        self.curveballClientMain = CurveballClientMain(
                self.qSettings,
                self.curveballClientSettings)

        # Add widgets to view
        self.setCentralWidget(self.curveballClientMain)
        self.addDockWidget(QtCore.Qt.TopDockWidgetArea, dock)
        self.viewMenu.addAction(dock.toggleViewAction())

        # Final formatting
        self.setWindowTitle("Curveball Client")
        self.setUnifiedTitleAndToolBarOnMac(True)

    def closeEvent(self, event):
        self.writeSettings()
        self.curveballClientMain.closeEvent(event)
        self.curveballClientSettings.closeEvent(event)
        return super(MainWindow, self).closeEvent(event)

    def readSettings(self):
        self.qSettings = QtCore.QSettings("BBN", "BBN Curveball")
        pos = self.qSettings.value("pos", QtCore.QPoint(200, 200))
        size = self.qSettings.value("size", QtCore.QSize(400, 400))
        self.resize(size)
        self.move(pos)

    def writeSettings(self):
        self.qSettings.setValue("pos", self.pos())
        self.qSettings.setValue("size", self.size())

    def createActions(self):
        self.exitAct = QtGui.QAction("Exit", self, shortcut="Ctrl+Q",
                triggered=self.close)

    def createMenus(self):
        # File
        self.fileMenu = self.menuBar().addMenu("File")
        self.fileMenu.addAction(self.exitAct)

        # View
        self.viewMenu = self.menuBar().addMenu("View")
        # the view menu will be populated by docking widgets

        self.menuBar().addSeparator()

        # Help
        self.helpMenu = self.menuBar().addMenu("Help")
        #self.helpMenu.addAction(self.aboutAct)
        #self.helpMenu.addAction(self.aboutQtAct)

    def createStatusBar(self):
        self.statusBar().showMessage("Ready")

def initTwisted():
    app = QtGui.QApplication(sys.argv)
    mainWin = MainWindow(cbdir)

    # Install Twisted Qt reactor
    # this allows Twisted to be driven by the Qt mainloop
    import cb.gui.qtreactor
    cb.gui.qtreactor.install()

    # If the main dialog closes, shut everything down
    # This wouldn't normally be necessary if we used the regular Qt
    # event loop but the twisted reactor calls a different qt event loop
    # which doesn't trigger the quit on last window closed signal
    from twisted.internet import reactor
    mainWin.curveballClientMain.closing.connect(reactor.stop)

    # make sure stopping twisted event also shuts down Qt
    reactor.addSystemEventTrigger('after', 'shutdown', app.quit)

    mainWin.show()
    sys.exit(app.exec_())

def init():
    app = QtGui.QApplication(sys.argv)
    mainWin = MainWindow()
    mainWin.show()
    sys.exit(app.exec_())

if __name__ == '__main__':
    init()
