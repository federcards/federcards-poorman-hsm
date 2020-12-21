#!/usr/bin/env python3

from PyQt5.QtWidgets import *

from .load_ui import GenericQt5Window, GenericQt5Dialog

class NewPINEntry(GenericQt5Dialog):
    def __init__(self):
        GenericQt5Dialog.__init__(self, "newpinentry")
        self.buttonBox.button(QDialogButtonBox.Ok).setEnabled(False)

    def show(self, *args, **kvargs):
        self.password.setText("")
        self.password2.setText("")
        GenericQt5Dialog.show(self)

    @GenericQt5Dialog.signal("password", "textChanged")
    def on_password_textChanged(self, *args, **kvargs):
        self.buttonBox.button(QDialogButtonBox.Ok).setEnabled(
            self.password.text() == self.password2.text() != ""
        )

    @GenericQt5Dialog.signal("password2", "textChanged")
    def on_password2_textChanged(self, *args, **kvargs):
        self.buttonBox.button(QDialogButtonBox.Ok).setEnabled(
            self.password.text() == self.password2.text() != ""
        )
