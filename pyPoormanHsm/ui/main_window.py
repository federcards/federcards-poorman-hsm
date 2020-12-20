#!/usr/bin/env python3

from PyQt5.QtWidgets import QMessageBox as msgbox

from .load_ui import GenericQt5Window, GenericQt5Dialog
from .pinentry import PINEntry
from .totp_display import TOTPDisplay



class MainWindow(GenericQt5Window):

    def __init__(self, app):
        self.totp_display = TOTPDisplay()
        self.pinentry_session_start = PINEntry()
        self.pinentry_unlock = PINEntry()
        self.app = app

        GenericQt5Window.__init__(self, "main_window")


    @GenericQt5Window.signal("mnuSessionStart", "triggered")
    def on_mnuSessionStart_triggered(self, s=False, *args, **kvargs):
        self.pinentry_session_start.show()

    @GenericQt5Window.signal("mnuCardUnlock", "triggered")
    def on_mnuCardUnlock_triggered(self, s=False, *args, **kvargs):
        self.pinentry_unlock.show()


    @GenericQt5Window.signal("pinentry_session_start", "accepted")
    def on_pinentry_session_start_accepted(self, *args, **kvargs):
        success = self.app.session_manager.start(
            password=self.pinentry_session_start.password.text()
        )
        if not success:
            msgbox.critical(
                self,
                "Authentication Failed",
                "Failed to establish a secure connection with smartcard. " + 
                "Most likely you have entered the wrong password."
            )

    @GenericQt5Window.signal("pinentry_unlock", "accepted")
    def on_pinentry_unlock_accepted(self, *args, **kvargs):
        success = self.app.session_manager.unlock(
            password=self.pinentry_unlock.password.text()
        )
        if not success:
            msgbox.critical(
                self,
                "Unlocking Failed",
                "Failed to unlock the smartcard. For security reason, the " +
                "card requires you to authenticate again."
            )

    # HMAC slots buttons
    @GenericQt5Window.signal("btnCalcHMACTOTP", "clicked")
    def on_btnCalcHMACTOTP_clicked(self, *args, **kvargs):
        selected = self.viewHMACSlots.selectedIndexes()
        if len(selected) < 1:
            msgbox.critical(
                self,
                "No Slots Selected",
                "Please choose one of the slots and try again."
            )
            return
        slot_id = selected[0].row()
        try:
            slot_stat = self.app.session_manager.hmac_slots.stat[slot_id]
        except:
            msgbox.critical(
                self,
                "Unknown Slot Status",
                "Try to restart the program."
            )
            return
        if slot_stat["immutable"] == True:
            msgbox.warning(
                self,
                "Immutable Slots",
                "Immutable slots have secrets that cannot be read out nor " +
                "changed. For this reason, it's mostly meaningless to " +
                "generate Time-based One Time Password(TOTP) with them, as "+
                "these numbers should be used for authentication with "+
                "websites etc. but are totally unpredictable -- unless you "+
                "want to just fetch some random numbers." 
            )
            
        self.totp_display.show(
            lambda d: self.app.session_manager.call_hmac_slot(slot_id, d))
