#!/usr/bin/env python3

from PyQt5.QtWidgets import QMessageBox as msgbox

from .load_ui import GenericQt5Window, GenericQt5Dialog
from .pinentry import PINEntry
from .newpinentry import NewPINEntry
from .totp_display import TOTPDisplay



class MainWindow(GenericQt5Window):

    def __init__(self, app):
        self.totp_display = TOTPDisplay()
        self.pinentry_session_start = PINEntry()
        self.pinentry_unlock = PINEntry()
        self.newpinentry_session = NewPINEntry()
        self.newpinentry_locking = NewPINEntry()
        
        self.app = app
        GenericQt5Window.__init__(self, "main_window")


    @GenericQt5Window.signal("mnuSessionStart", "triggered")
    def on_mnuSessionStart_triggered(self, s=False, *args, **kvargs):
        self.pinentry_session_start.show()

    @GenericQt5Window.signal("mnuCardUnlock", "triggered")
    def on_mnuCardUnlock_triggered(self, s=False, *args, **kvargs):
        self.pinentry_unlock.show()

    @GenericQt5Window.signal("mnuSessionChangeSharedsecret", "triggered")
    def on_mnuSessionChangeSharedsecret_triggered(self, s=False, *args, **kvargs):
        msgbox.information(
            self,
            "Changing Session Sharedsecret",
            "Session sharedsecret is used for AUTHENTICATION. It establishes "+
            "encrypted communication with card and prevents potential "+
            "wiretapping. Losing this password will block you from using "+
            "this card, be careful!"
        )
        self.newpinentry_session.show()

    @GenericQt5Window.signal("mnuCardChangePassword", "triggered")
    def on_mnuCardChangePassword_triggered(self, s=False, *args, **kvargs):
        msgbox.information(
            self,
            "Changing Card Encryption",
            "You are about to change the encryption password for this card. "+
            "MAKE SURE TO CHOOSE A VERY STRONG PASSWORD! "+
            "And remember it! There is NO recovery if you lose this password!"
        )
        self.newpinentry_locking.show()


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

    @GenericQt5Window.signal("newpinentry_session", "accepted")
    def on_newpinentry_session_accepted(self, *args, **kvargs):
        success = self.app.session_manager.change_session_sharedsecret(
            password=self.newpinentry_session.password.text()
        )
        if success:
            msgbox.information(
                self,
                "Success",
                "Sharedsecret for authentication changed successfully."
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

    @GenericQt5Window.signal("newpinentry_locking", "accepted")
    def on_newpinentry_locking_accepted(self, *args, **kvargs):
        success = self.app.session_manager.change_locking_password(
            password=self.newpinentry_locking.password.text()
        )
        if success:
            msgbox.information(
                self,
                "Success",
                "Card encryption password changed successfully."
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
