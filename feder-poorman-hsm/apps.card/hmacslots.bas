' HMAC slots subsystem(HMS)
' -------------------------
' HMAC slots are slots configured with secret keys. It generates HMAC hashes
' for a given input with these keys.
' These slots are useful for generating challenge-response value, or HOTP/TOTP
' authentication.
'
' There are 2 types of slots. Numbered with 0-7 and 8-31. The lower 8 slots are
' slots with unpredictable random values. They are specific to this card and
' their secrets are randomly generated. Upon request these secrets can be
' regenerated. The higher 24 slots can be assigned with secrets.
'
' The secrets set with each slot cannot be read out. Also this subsystem
' requires the "lock" subsystem for offline on-card encryption.

CONST HMS_IMMUTABLE_SLOTS = 8
CONST HMS_SLOTS_TOTAL = 32
CONST HMS_STAT_SLOTIMMUTABLE = &H80
CONST HMS_STAT_SLOTUSED = &H01

EEPROM HMS_SECRETS_ENCRYPTED(HMS_SLOTS_TOTAL) as STRING
EEPROM HMS_LABELS(HMS_SLOTS_TOTAL) as STRING

SUB HMS_SET_VALUE(id AS BYTE, k as STRING, secret as STRING)
    HMS_SECRETS_ENCRYPTED(id) = crypto_encrypt(k, secret)
END SUB

FUNCTION HMS_GET_VALUE(id AS BYTE, k as STRING) as STRING
    HMS_GET_VALUE = crypto_decrypt(k, HMS_SECRETS_ENCRYPTED(id))
END FUNCTION



' Command: HMS_STAT
' -----------------
COMMAND &HF0 &H00 HMS_STAT(LC=0, data as string)
    IF GRD_SESSION_ACTIVE() = &H00 THEN
        data = GRD_RESPONSE(S_ERROR, "UNAUTHORIZED", 0)
        EXIT COMMAND
    END IF
    
    data = ""
    
    PRIVATE i as BYTE
    PRIVATE r as BYTE
    FOR i = 0 TO HMS_SLOTS_TOTAL - 1
        r = 0
        IF HMS_SECRETS_ENCRYPTED(i) <> "" THEN
            r = r OR HMS_STAT_SLOTUSED
        END IF
        IF i < HMS_IMMUTABLE_SLOTS THEN
            r = r OR HMS_STAT_SLOTIMMUTABLE
        END IF
        data = data + chr$(r)
    NEXT
    
    data = GRD_RESPONSE(S_OK, data, GRD_OPTION_CREDENTIAL)
END COMMAND



' Command: HMS_HASH
' -----------------
' Input is a string. The first byte is the index of slot want to use. The rest
' are data to be calculated with HMAC.
COMMAND &HF0 &H02 HMS_HASH(data as string)
    PRIVATE data_decrypted as STRING
    data_decrypted = GRD_DECRYPT(data)
    
    IF data_decrypted = "" THEN
        data = GRD_RESPONSE(S_ERROR, "UNAUTHORIZED", 0)
        EXIT COMMAND
    END IF
    
    ' Otherwise, we got authorized command input.
    
    PRIVATE decrypt_key as STRING
    decrypt_key = LCK_GET_KEY()
    IF decrypt_key = "" THEN
        data = GRD_RESPONSE(S_ERROR, "UNLOCK REQUIRED", 0)
        EXIT COMMAND
    END IF
    
    PRIVATE hmac_index as BYTE
    hmac_index = asc(data_decrypted(1)) mod HMS_SLOTS_TOTAL
    
    PRIVATE hmac_secret as STRING
    hmac_secret = HMS_GET_VALUE(hmac_index, decrypt_key)
    
    IF hmac_secret = "" THEN
        IF hmac_index < HMS_IMMUTABLE_SLOTS THEN
            ' Initialize the slot on the fly. Just put random bytes.
            hmac_secret = crypto_random32bytes()
            call HMS_SET_VALUE(hmac_index, decrypt_key, hmac_secret)
        ELSE
            data = GRD_RESPONSE(S_ERROR, "UNINITIALIZED", 0)
            EXIT COMMAND
        END IF
    END IF
    
    data = GRD_RESPONSE(_
        S_OK,_
        HMAC_SHA1(hmac_secret, Mid$(data_decrypted, 2)),_
        GRD_OPTION_CREDENTIAL)
END COMMAND



' Command: HMS_SET_SLOT
' ---------------------
' Set the secret for a given slot. First byte of input being the slot wanted to
' set, the rest being the secret. Slot id must be >= 8 and <= 31.
COMMAND &HF0 &H04 HMS_SET_SLOT(data as string)
    PRIVATE data_decrypted as STRING
    data_decrypted = GRD_DECRYPT(data)
    IF data_decrypted = "" THEN
        data = GRD_RESPONSE(S_ERROR, "UNAUTHORIZED", 0)
        EXIT COMMAND
    END IF
    
    ' Otherwise, we got authorized command input.
    PRIVATE decrypt_key as STRING
    decrypt_key = LCK_GET_KEY()
    IF decrypt_key = "" THEN
        data = GRD_RESPONSE(S_ERROR, "UNLOCK REQUIRED", 0)
        EXIT COMMAND
    END IF
    
    PRIVATE hmac_index as BYTE
    hmac_index = asc(data_decrypted(1)) mod HMS_SLOTS_TOTAL
    IF hmac_index < HMS_IMMUTABLE_SLOTS OR hmac_index >= HMS_SLOTS_TOTAL THEN
        data = GRD_RESPONSE(S_ERROR, "INVALID SLOT", 0)
        EXIT COMMAND
    END IF
    
    call HMS_SET_VALUE(hmac_index, decrypt_key, Mid$(data_decrypted, 2))
    data = GRD_RESPONSE(_
        S_OK,_
        HMAC_SHA1(HMS_GET_VALUE(hmac_index, decrypt_key), "OK"),_
        GRD_OPTION_CREDENTIAL)
END COMMAND



' Command: HMS_SLOT_LABEL_SET
' -----------------------
' Label the given slot with some text. Note: this does not require unlocking.
COMMAND &HF0 &H06 HMS_SLOT_LABEL_SET(data as string)
    PRIVATE data_decrypted as STRING
    data_decrypted = GRD_DECRYPT(data)
    IF data_decrypted = "" THEN
        data = GRD_RESPONSE(S_ERROR, "UNAUTHORIZED", 0)
        EXIT COMMAND
    END IF
    
    PRIVATE slot_index as BYTE
    slot_index = asc(data_decrypted(1)) mod HMS_SLOTS_TOTAL
    HMS_LABELS(slot_index) = Mid$(data_decrypted, 2)

    data = GRD_RESPONSE(S_OK, "OK", GRD_OPTION_CREDENTIAL)
END COMMAND



' Command: HMS_SLOT_LABEL_GET
' ---------------------------
COMMAND &HF0 &H08 HMS_SLOT_LABEL_GET(data as string)
    PRIVATE data_decrypted as STRING
    data_decrypted = GRD_DECRYPT(data)
    IF data_decrypted = "" THEN
        data = GRD_RESPONSE(S_ERROR, "UNAUTHORIZED", 0)
        EXIT COMMAND
    END IF
    
    PRIVATE slot_index as BYTE
    slot_index = asc(data_decrypted(1)) mod HMS_SLOTS_TOTAL
    data = GRD_RESPONSE(S_OK, HMS_LABELS(slot_index), GRD_OPTION_CREDENTIAL)
END COMMAND


