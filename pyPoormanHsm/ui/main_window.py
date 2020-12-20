#!/usr/bin/env python3
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
        self.app.session_manager.start(
            password=self.pinentry_session_start.password.text()
        )

    @GenericQt5Window.signal("pinentry_unlock", "accepted")
    def on_pinentry_unlock_accepted(self, *args, **kvargs):
        self.app.session_manager.unlock(
            password=self.pinentry_unlock.password.text()
        )

    # HMAC slots buttons
    @GenericQt5Window.signal("btnCalcHMACTOTP", "clicked")
    def on_btnCalcHMACTOTP_clicked(self, *args, **kvargs):
        print("**")
        selected = self.viewHMACSlots.selectedIndexes()
        if len(selected) < 1: return # TODO error
        slot_id = selected[0].row()
        print("***")
        self.totp_display.show(
            lambda d: self.app.session_manager.call_hmac_slot(slot_id, d))
