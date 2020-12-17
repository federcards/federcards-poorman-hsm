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
EEPROM HMS_SECRETS_ENCRYPTED(32) as STRING


COMMAND &HF0 &H00 HMS_HASH(data as string)
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
    hmac_index = asc(data_decrypted(1)) mod 32
    
    PRIVATE hmac_secret as STRING
    hmac_secret = crypto_decrypt(decrypt_key, HMS_SECRETS_ENCRYPTED(hmac_index))
    
    IF hmac_secret = "" THEN
        IF hmac_index < HMS_IMMUTABLE_SLOTS THEN
            hmac_secret = crypto_random32bytes()
            HMS_SECRETS_ENCRYPTED(hmac_index) = _
                crypto_encrypt(decrypt_key, hmac_secret)
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


