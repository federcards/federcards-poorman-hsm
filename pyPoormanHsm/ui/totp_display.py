#!/usr/bin/env python3

import time
from PyQt5.QtCore import *
from PyQt5.QtWidgets import QMessageBox as msgbox

from .load_ui import GenericQt5Window, GenericQt5Dialog


class TOTPDisplay(GenericQt5Dialog):

    def __init__(self):
        self.refresh_func = None
        self.timer = QTimer()
        
        self.display_digits = 6 
        self.display_seed = None
        self.display_timeslice = 0

        # Parameters previously used for generating display. Used for checking
        # if display needs update.
        self.display_parameters = None 

        GenericQt5Dialog.__init__(self, "totp_display")

    def show(self, refresh_func):
        self.lblTOTP.setText("Waiting...")
        self.display_parameters = None
        self.display_seed = None
        self.display_timeslice = 0

        self.refresh_func = refresh_func
        self.timer.start(500)
        GenericQt5Dialog.show(self)

    @GenericQt5Dialog.signal(None, "finished")
    def on_finished(self, *args, **kvargs):
        self.timer.stop()

    @GenericQt5Dialog.signal("dialDigits", "valueChanged")
    def on_dial_valueChanged(self, *args, **kvargs):
        self.display_digits = self.dialDigits.value() 

    @GenericQt5Dialog.signal("timer", "timeout")
    def on_timer(self, *args, **kvargs):
        if not self.isVisible(): return
        if not self.refresh_func: return

        now = int(time.time())
        timeslice = now // 30

        if timeslice != self.display_timeslice:
            # refresh
            try:
                self.display_seed = self.refresh_func(
                    self.int_to_bytestring(timeslice))
                assert self.display_seed.statusCode == 0
                self.display_seed = bytes(self.display_seed)
                self.display_timeslice = timeslice
            except:
                msgbox.critical(
                    self, 
                    "Slot Not Initialized",
                    "This slot has not been initialized. Please set a secret first."
                )
                self.accept()
                return

        p = (self.display_digits, self.display_seed)
        if p != self.display_parameters:
            self.display_parameters = p
            self.lblTOTP.setText(
                self.generate_otp(self.display_seed, self.display_digits))
        
        self.pbRemainingSeconds.setValue(30 - now % 30)

    def int_to_bytestring(self, i, padding=8):
        """
        Turns an integer to the OATH specified bytestring, which is fed to
        the HMAC along with the secret
        """
        result = bytearray()
        while i != 0:
            result.append(i & 0xFF)
            i >>= 8
        # It's necessary to convert the final result from bytearray to bytes
        # because the hmac functions in python 2.6 and 3.3 don't work with
        # bytearray
        return bytes(bytearray(reversed(result)).rjust(padding, b'\0'))

    def generate_otp(self, hmac_hash, digits=6):
        hmac_hash = bytearray(hmac_hash)
        offset = hmac_hash[-1] & 0xf
        code = ((hmac_hash[offset] & 0x7f) << 24 |
                (hmac_hash[offset + 1] & 0xff) << 16 |
                (hmac_hash[offset + 2] & 0xff) << 8 |
                (hmac_hash[offset + 3] & 0xff))
        str_code = str(code % 10 ** digits)
        return str_code.rjust(digits, "0")
