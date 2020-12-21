#!/usr/bin/env python3
from .load_ui import GenericQt5Window, GenericQt5Dialog

class PINEntry(GenericQt5Dialog):
    def __init__(self):
        GenericQt5Dialog.__init__(self, "pinentry")

    def show(self, *args, **kvargs):
        self.password.setText("")
        GenericQt5Dialog.show(self)
