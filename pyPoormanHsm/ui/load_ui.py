#!/usr/bin/env python3

import os
import sys
from PyQt5 import uic
from PyQt5.QtWidgets import QMainWindow, QDialog


uifile = lambda f: os.path.join(
    os.path.dirname(os.path.realpath(sys.argv[0])),
    "qt5_gui_designs", "%s.ui" % f)


class WindowSignaling:

    class SignalCallback:
        def __init__(self, func, target, signal):
            self.func = func
            self.target = target
            self.signal = signal 

    def signal(targetobj, signalname):
        # decorates a function, marking it to be a signal handler
        def decorator(func):
            return WindowSignaling.SignalCallback(func, targetobj, signalname)
        return decorator

    def bind_signals(self):
        for name in dir(self):
            signal_callback = getattr(self, name)
            if not isinstance(signal_callback, WindowSignaling.SignalCallback): continue
            
            def bind(signal_callback):
                if signal_callback.target != None:
                    target = getattr(self, signal_callback.target)
                else:
                    target = self
                target_signal = getattr(target, signal_callback.signal)
                target_signal.connect(
                    lambda *args, **kvargs:\
                        signal_callback.func(self, *args, **kvargs))
            bind(signal_callback)
    



class GenericQt5Window(QMainWindow, WindowSignaling):

    def __init__(self, ui_name):
        QMainWindow.__init__(self)
        uic.loadUi(uifile(ui_name), self)
        self.bind_signals()


class GenericQt5Dialog(QDialog, WindowSignaling):

    def __init__(self, ui_name):
        QDialog.__init__(self)
        uic.loadUi(uifile(ui_name), self)
        self.bind_signals()
