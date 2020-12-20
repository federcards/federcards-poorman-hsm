#!/usr/bin/env python3

import os
import hashlib

from smartcard.ATR import ATR
from smartcard.CardType import ATRCardType
from smartcard.CardRequest import CardRequest
from .crypto import crypto_encrypt, crypto_decrypt, AES, ShaHash, HMAC_SHA1


I_ENCRYPTED = 0x01



class CardIOError(IOError):

    def __init__(self, sw1, sw2, data):
        IOError.__init__(self, data)
        self.sw1 = sw1
        self.sw2 = sw2
        self.sw1sw2 = (sw1 << 8) | sw2
        self.data = data


"""

Declare Command &H00 &H00 GRD_GETINFO(LC=0, data as string)
Declare COMMAND &H00 &H02 GRD_PREAUTH(LC=0, ret as STRING)
Declare COMMAND &H00 &H04 GRD_AUTH(data as STRING)
Declare COMMAND &H00 &H06 GRD_UPDATE_SHAREDSECRET(data as STRING)

Declare COMMAND &H02 &H00 LCK_UNLOCK(data as STRING)
Declare COMMAND &H02 &H02 LCK_LOCK(data as STRING)
Declare COMMAND &H02 &H04 LCK_CHANGE_KEY(data as string)

Declare COMMAND &HF0 &H00 HMS_HASH(data as string)
Declare COMMAND &HF0 &H02 HMS_SET_SLOT(data as string)
"""


class CardResponse:

    def __init__(self, decryptor, raw_data, result_parser=None):
        self.encrypted = (raw_data[0] == 0xFF) 
        payload = raw_data[1:]

        if self.encrypted:
            try:
                payload = decryptor(payload)
                assert payload != ""
            except:
                raise Exception("Decryption error.")

        self.statusCode = payload[0]
        self.payload = payload[1:]
        self.result = \
            result_parser(self, self.payload) if result_parser else None

    def __bytes__(self):
        return self.payload

    def __repr__(self):
        return "[CARD RESPONSE %s - %x || %s]" % (
            "" if not self.encrypted else "(ENCRYPTED)",
            self.statusCode,
            self.payload.hex()\
                if self.statusCode == 0 else self.payload.decode("ascii")
        )




class CardIO:

    ATR = b"feder.cards/ph1"

    def command(CLA, INS, options=0):
        def commandWrapper(commandFunc):
            def commandCaller(*args):
                self = args[0]
                data = args[1] if len(args) > 1 else b""

                if options & I_ENCRYPTED:
                    if self.session_encrypt == None:
                        raise Exception("GRD Session inactive.")
                    data = self.session_encrypt(data)
                    print("I_E", data)
                sw1, sw2, response = self._sendCommandRaw(CLA, INS, data)
                return CardResponse(
                    self.session_decrypt,
                    raw_data=response,
                    result_parser=commandFunc
                )
            return commandCaller
        return commandWrapper


    def __init__(self):
        self.cardRequest = CardRequest(timeout=10) #, cardType=cardtype)
        self.__key = None
        self.session_decrypt = None

    def _sendCommandRaw(self, CLA, INS, data=b''):
        assert type(data) == bytes
        
        data = list(data)
        # See ISO7816-3. APDU begins with CLA, INS, P1, P2 and ends with
        # an expected count of response bytes. If there's data to send,
        # after the 4-bytes header there's a count of request bytes followed
        # by actual data. Otherwise, both are skipped.
        # In our case, CLA and INS are arguments, P1=P2=0, and always expecting
        # maximum response size(0xFE=254 bytes).
        if data:
            apdu = [CLA, INS, 0x00, 0x00, len(data)] + data + [0xFE]
        else:
            apdu = [CLA, INS, 0x00, 0x00, 0xFE]

        response, sw1, sw2 = self.cardService.connection.transmit(apdu)
        response = bytes(response)

        if not ((sw1 == 0x90 and sw2 == 0x00) or sw1 == 0x61):
            raise CardIOError(sw1=sw1, sw2=sw2, data=response)

        return sw1, sw2, response


    def waitForCard(self):
        self.cardService = self.cardRequest.waitforcard()

        self.cardService.connection.connect()
        atr = ATR(self.cardService.connection.getATR())
        identification = bytes(atr.getHistoricalBytes())

        if identification != self.ATR:
            raise Exception("Wrong card inserted.")


    def __enter__(self, *args, **kvargs):
        self.waitForCard()
        return self

    def __exit__(self, *args, **kvargs):
        pass

    def __deriveSharedsecretFromPassword(self, password):
        n, r, p = 1048576, 8, 1
        return hashlib.scrypt(
            password, salt=self.ATR, n=n, r=r, p=p, dklen=32, maxmem=2*n*r*65)

    def __deriveDecryptionKeyFromPassword(self, password):
        n, r, p = 1048576, 8, 1
        return hashlib.scrypt(
            password,
            salt=self.ATR + b"/decryption",
            n=n, r=r, p=p, dklen=32, maxmem=2*n*r*65)

    """Definitions of commands. Each command takes a preprocessed (e.g.
    decrypted) input."""

    @command(0x00, 0x00)
    def GRD_GETINFO(self, data): return data

    @command(0x00, 0x02)
    def GRD_PREAUTH(self, data): return data

    @command(0x00, 0x04)
    def GRD_AUTH(self, data): return data

    @command(0x00, 0x06, I_ENCRYPTED)
    def GRD_UPDATE_SHAREDSECRET(self, data): return data


    @command(0x02, 0x00, I_ENCRYPTED)
    def LCK_UNLOCK(self, data): return data
    
    @command(0x02, 0x02, I_ENCRYPTED)
    def LCK_LOCK(self, data): return data

    @command(0x02, 0x04, I_ENCRYPTED)
    def LCK_CHANGE_KEY(self, data): return data


    @command(0xF0, 0x00, I_ENCRYPTED)
    def HMS_STAT(self, data):
        ret = []
        i = 0
        for b in data:
            ret.append({
                "id":        i,
                "immutable": bool(b & 0x80),
                "used":      bool(b & 0x01),
            })
            i += 1
        return ret 

    @command(0xF0, 0x02, I_ENCRYPTED)
    def HMS_HASH(self, data): return data

    @command(0xF0, 0x04, I_ENCRYPTED)
    def HMS_SET_SLOT(self, data): return data

    @command(0xF0, 0x06, I_ENCRYPTED)
    def HMS_SLOT_LABEL_SET(self, data): return data

    @command(0xF0, 0x08, I_ENCRYPTED)
    def HMS_SLOT_LABEL_GET(self, data): return data


    def authenticate(self, sharedsecret=None):
        if not sharedsecret:
            sharedsecret = b'\x00' * 32
        else:
            sharedsecret = self.__deriveSharedsecretFromPassword(sharedsecret)
        assert len(sharedsecret) == 32
        preauth = bytes(self.GRD_PREAUTH())

        challenge = AES(-256, sharedsecret, preauth) 

        # Generate user side random, and thus the user side session key
        user_rand = os.urandom(16)
        user_rand_encrypt_key = ShaHash(
            challenge + sharedsecret).ljust(32, b"\x00")
        session_key = ShaHash(
            user_rand + challenge + sharedsecret).ljust(32, b"\x00")
        sha1_session_key = ShaHash(session_key)

        self.session_decrypt = lambda d: crypto_decrypt(session_key, d)
        self.session_encrypt = lambda d: crypto_encrypt(session_key, d)

        #Present the hashcash for this proposed session key.
        i = 0
        while True:
            hashcash = hex(i).rjust(20, " ").encode("ascii")
            i+=1
            hashcash_sha1 = ShaHash(hashcash + session_key)
            if hashcash_sha1[0] == 0 and hashcash_sha1[1] == 0 and hashcash_sha1[2] < 16:
                break

        # Send the result and validate authentication process
        assert len(hashcash) == 20
        answer = hashcash + AES(256, user_rand_encrypt_key, user_rand) + sha1_session_key
        expected_ret = HMAC_SHA1(session_key, b"OK")

        if bytes(self.GRD_AUTH(answer)) ==  expected_ret:
            print("Authentication successful.")
            return True
        else:
            self.session_decrypt, self.session_encrypt = None, None
            return False


    def changeSharedsecret(self, sharedsecret):
        return self.GRD_UPDATE_SHAREDSECRET(
            self.__deriveSharedsecretFromPassword(sharedsecret))


    def unlock(self, password=None):
        if not password:
            password = b"\x00" * 32
        else:
            password = self.__deriveDecryptionKeyFromPassword(password)
        return bytes(self.LCK_UNLOCK(password)).startswith(b'OK')

    def changeUnlockKey(self, password):
        password = self.__deriveDecryptionKeyFromPassword(password)
        return self.LCK_CHANGE_KEY(password)



if __name__ == "__main__":
    with CardIO() as c:
        if not c.authenticate(b"test"):
            print("Authentication failure.")
            exit()

        if not c.unlock(b"password"):
            print("Unlocking failure.")
            exit()

