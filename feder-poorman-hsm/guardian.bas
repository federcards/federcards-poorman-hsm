' Guardian Subsystem (GRD)
' ------------------------
' Guardian Subsystem (GRD) is the subsystem implementing card message encryption
' with user. This system replaces secure messaging functionality, which is not
' always available on different cards.
'
' GRD starts with user authentication. The authentication is based on a
' sharedsecret on card, which can be changed after a session is established.
'
' The session starts when authentication is finished successfully. The user and
' the card establish agreement on a session key during this process. This key
' will be used for all future communication with GRD or other subsystem.


TYPE TYPE_GRD_STATUS
    SESSION_INITIALIZED as BYTE ' tells if RAND_CARD is present
    RAND_CARD as string*16
    CHALLENGE_CARD as string*16
    SESSION_KEY as string*32
    SESSION_ACTIVE as BYTE      ' tells if SESSION_KEY is negotiated and ready
END TYPE

' holder of card session status
PUBLIC VAR_GRD_STATUS as TYPE_GRD_STATUS = 0, "", "", "", 0




' The shared secret for secure messaging.
EEPROM VAR_GRD_SHAREDSECRET as STRING*32
CONST GRD_HASHCASH_REQUIREMENT = 20


'###############################################################################
' Internal functions and subroutines


' Subroutine: GRD_SESSION_INIT
' ----------------------------
' Initialize the session, generates a new RAND_CARD, and marks
' CARD_SESSION_INITIALIZED = 1. 
SUB GRD_SESSION_INIT()
    IF VAR_GRD_STATUS.SESSION_INITIALIZED = &HFF THEN 
        EXIT SUB
    END IF

    VAR_GRD_STATUS.RAND_CARD = crypto_random_bytes(16)  ' Randomize
    VAR_GRD_STATUS.CHALLENGE_CARD = AES(_               ' Calculate challenge
        256, VAR_GRD_SHAREDSECRET, VAR_GRD_STATUS.RAND_CARD)
    VAR_GRD_STATUS.SESSION_INITIALIZED = &HFF           ' Mark as initialized
END SUB



' Subroutine: GRD_SESSION_RESET
'-----------------------------
' Reset the session to default status. The user needs to authenticate again.
SUB GRD_SESSION_RESET()
    VAR_GRD_STATUS.SESSION_INITIALIZED = 0
    VAR_GRD_STATUS.SESSION_KEY = ""
    VAR_GRD_STATUS.SESSION_ACTIVE = 0
END SUB



' Function GRD_HASHCASH_COUNT
' ---------------------------
' Counts the leading zeros after SHA1 of a given string.
FUNCTION GRD_HASHCASH_COUNT(ByVal s as STRING) as BYTE
    DIM PREFIX_ZEROS(8) as BYTE = &HFF,&H7F,&H3F,&H1F,&H0F,&H07,&H03,&H01,&H00
    PRIVATE i as BYTE
    PRIVATE j as BYTE
    GRD_HASHCASH_COUNT = 0
    s = ShaHash(s)
    FOR i = 1 to 20
        FOR j = 8 to -1 STEP -1
            IF (Asc(s(i)) OR PREFIX_ZEROS(j)) = PREFIX_ZEROS(j) THEN
                GRD_HASHCASH_COUNT = GRD_HASHCASH_COUNT + j
                IF j = 8 THEN
                    EXIT FOR
                ELSE
                    EXIT FUNCTION
                END IF
            END IF
        NEXT
    NEXT
END FUNCTION



' Function GRD_DECRYPT
' --------------------
' Decrypt commands sent from user.
FUNCTION GRD_DECRYPT(data as string) as STRING
    IF VAR_GRD_STATUS.SESSION_ACTIVE <> &HFF OR Len(data) <= CRYPTO_OVERHEAD THEN
        GRD_DECRYPT = ""
        EXIT FUNCTION
    END IF
    GRD_DECRYPT = crypto_decrypt(VAR_GRD_STATUS.SESSION_KEY, data)
END FUNCTION



' Function GRD_ENCRYPT
' --------------------
' Encrypt data for replying user.
FUNCTION GRD_ENCRYPT(data as string) as STRING
    IF VAR_GRD_STATUS.SESSION_ACTIVE <> &HFF THEN
        GRD_ENCRYPT = ""
        EXIT FUNCTION
    END IF
    GRD_ENCRYPT = crypto_encrypt(VAR_GRD_STATUS.SESSION_KEY, data)
END FUNCTION



'###############################################################################
' COMMANDS EXPOSED


' Command: GRD_GETINFO
' --------------------
' Returns information on card status.
COMMAND &H00 &H00 GRD_GETINFO(LC=0, ret as STRING)
    ret = Chr$(VAR_GRD_STATUS.SESSION_INITIALIZED)
END COMMAND



' Command: GRD_PREAUTH
' --------------------
' Called before a user attempts to authenticate itself with the card. Returns an
' encrypted value of RAND_CARD.
COMMAND &H00 &H02 GRD_PREAUTH(LC=0, ret as STRING)
    call GRD_SESSION_INIT()
    ret = VAR_GRD_STATUS.CHALLENGE_CARD
END COMMAND



' Command: GRD_AUTH
' -----------------
' Called when the user wants to authenticate itself with the card. The user
' supplies 3 parameters:
'   +------------------------------------------------------------------+
'   | Special Nonce | Encrypted User Random Seed | SHA1 of Session Key |
'   |     20 bytes  |          16 bytes          |      20 bytes       |
'   +------------------------------------------------------------------+
' * Special Nonce is a random value, that, when combined with Session Key, will
'   produce a SHA1 value beginning with 20-bits of zeros:
'       SHA1(Special Nonce, Session Key) = 00000... (in hex)
' * User Random Seed is decrypted with SHA1(RAND_CARD + SHAREDSECRET), padded
'   with zeros at end to 32 bytes.
' * Session Key = SHA1(User Random Seed + RAND_CARD + SHAREDSECRET), padded with
'   zeros at end to 32 bytes.
' * SHA1(Session Key) is validated against user input.
COMMAND &H00 &H04 GRD_AUTH(data as STRING)
    IF Len(data) <> 56 THEN
        data = "BAD REQUEST"
        EXIT COMMAND
    END IF
    
    PRIVATE special_nonce as STRING*20
    PRIVATE user_rand as STRING*16
    PRIVATE sha1_session_key as STRING*20
    PRIVATE buf_32 as STRING*32
    
    special_nonce = Left$(data, 20)
    user_rand = Mid$(data, 21, 16)
    sha1_session_key = Right$(data, 20)
    
    ' Decrypt user rand
    buf_32 = ShaHash(VAR_GRD_STATUS.RAND_CARD + VAR_GRD_SHAREDSECRET)
    user_rand = AES(-256, buf_32, user_rand)
    
    ' Generate session key
    buf_32 = ShaHash(user_rand + VAR_GRD_STATUS.RAND_CARD + VAR_GRD_SHAREDSECRET)
    
    ' Validate hashcash in special nonce against session key. This prevents
    ' guessing the sharedsecret by increasing user's calculation effort.
    PRIVATE hashcash_count as BYTE
    hashcash_count = GRD_HASHCASH_COUNT(special_nonce + buf_32)
    IF hashcash_count < GRD_HASHCASH_REQUIREMENT THEN
        call GRD_SESSION_RESET()
        data = "HASHCASH INSUFFICIENT"
        EXIT COMMAND
    END IF
    
    ' Validate session key
    IF strcmp_64(ShaHash(buf_32), sha1_session_key) = 0 THEN
        call GRD_SESSION_RESET()
        data = "FAILED"
        EXIT COMMAND
    END IF
    
    ' Returns HMAC signed "OK" with session key.
    VAR_GRD_STATUS.SESSION_KEY = buf_32
    VAR_GRD_STATUS.SESSION_ACTIVE = &HFF
    data = HMAC_SHA1(VAR_GRD_STATUS.SESSION_KEY, "OK")
END COMMAND



' Command: GRD_UPDATE_SHAREDSECRET
' --------------------------------
' Changes the shared secret. This must be done when a session is established,
' and the new secret MUST be 32 bytes.
' Returns "OK" or "FAILED" in string. When the sharedsecret is changed
' successfully, the current session is reset and the user must start it again.
COMMAND &H00 &H06 GRD_UPDATE_SHAREDSECRET(data as STRING)
    PRIVATE new_sharedsecret as STRING
    new_sharedsecret = GRD_DECRYPT(data)
    IF Len(new_sharedsecret) <> 32 THEN
        data = "FAILED"
        EXIT COMMAND
    END IF
    VAR_GRD_SHAREDSECRET = new_sharedsecret
    CALL GRD_SESSION_RESET()
    data = "OK"
END COMMAND







