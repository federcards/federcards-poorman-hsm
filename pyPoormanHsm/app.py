#!/usr/bin/env python3

import os
import sys

from PyQt5 import QtCore, QtGui
from PyQt5.QtCore import *
from PyQt5.QtGui import *
from PyQt5.QtWidgets import QApplication, QMessageBox as msgbox

from .cardio import *
from .ui import *


class HMACSlotsModel(QStandardItemModel):

    def __init__(self, app, session):
        super(HMACSlotsModel, self).__init__()

        self.app = app
        self.session = session
        self.initialized = False

        self.stat = []

    def refresh_by_card(self):
        card = self.session.card_io
        self.initialized = False
        if not card:
            return

        self.stat = [] 
        try:
            self.stat = card.HMS_STAT().result
            self.initialized = True
        except:
            return

        self.clear()
        self.setHorizontalHeaderLabels(["ID", "Immutable", "Label"])
        for stat in self.stat:
#            label = card.HMS_SLOT_LABEL_GET(bytes([stat["id"]]))
            label = b"(Click to view)"
            self.appendRow([
                QStandardItem(str(stat["id"])),
                QStandardItem("Yes" if stat["immutable"] else "No"),
                QStandardItem(bytes(label).decode("ascii")),
            ])





class SessionManager:

    def __init__(self, app, windows):
        self.app = app
        self.windows = app.windows

        self.card_io = None
        self.status_session_started = False
        self.status_unlocked = False

        self.hmac_slots = HMACSlotsModel(app=app, session=self)
        self.windows["main"].viewHMACSlots.setModel(self.hmac_slots)

        self.change_status(session_started=False) # final

    def change_status(self, session_started=None, unlocked=None):
        if None != session_started:
            self.status_session_started = session_started
        if None != unlocked:
            self.status_unlocked = unlocked

        main = self.windows["main"]
        main.tabResources.setEnabled(self.status_session_started)
        main.mnuSessionChangeSharedsecret.setEnabled(
            self.status_session_started)
        main.mnuLocking.setEnabled(self.status_session_started)
        main.mnuCardChangePassword.setEnabled(
            self.status_session_started and self.status_unlocked)

        for t in [
            main.btnCalcHMACTOTP,
            main.btnCalcHMACHOTP,
            main.btnCalcHMACGeneric,
            main.btnHMACEdit,
        ]:
            t.setEnabled(self.status_session_started and self.status_unlocked)

        main.statusBar.showMessage(
            "Authenticated."\
                if self.status_session_started else "Authentication required."
        )

        self.hmac_slots.refresh_by_card()


    def start(self, password):
        try:
            self.card_io = CardIO()
            self.card_io.waitForCard()
        except:
            return
        if self.card_io.authenticate(password.encode("ascii") or None):
            self.change_status(session_started=True)
            return True
        return False

    def unlock(self, password):
        if not self.card_io:
            return
        if self.card_io.unlock(password.encode("ascii") or None):
            self.change_status(unlocked=True)
            return True
        else:
            self.change_status(unlocked=False, session_started=False)
            return False

    def change_session_sharedsecret(self, password):
        return self.card_io.changeSharedsecret(
            password.encode("ascii") or None).statusCode == 0

    def change_locking_password(self, password):
        return self.card_io.changeUnlockKey(
            password.encode("ascii") or None).statusCode == 0

    def call_hmac_slot(self, slot_id, data):
        return self.card_io.HMS_HASH(bytes([slot_id]) + data)




class Application:

    def __init__(self):
        
        self.qapp = QApplication(sys.argv)
        self.windows = {
            'main': MainWindow(app=self),
        }
        self.windows['main'].show()

        self.session_manager = SessionManager(app=self, windows=self.windows)

        self.qapp.exec_()
