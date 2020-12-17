' Lock Subsystem (LCK)
' --------------------
' The lock subsystem provides on-card, offline encryption for secrets of other
' subsystems. It's a (un-)lockable deterministic key generator for these
' subsystems.
'
' The lock subsytem provides no locking mechanism if attempts failed for
' unlocking. However, each failed unlocking must results in the Guardian
' subsystem being reset.

CONST LCK_DEFAULT_USERKEY = chr$(_
    &H00,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H00,_
    &H00,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H00,_
    &H00,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H00,_
    &H00,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H00)

' LCK_MAIN_SECRET_ENCRYPTED
EEPROM LCK_MAIN_SECRET_ENCRYPTED as STRING*(1+(32+CRYPTO_OVERHEAD)*3)


' __LCK_MAIN_STATUS: Main status for this module.
TYPE TYPE_LCK_STATUS
    UNLOCKED as BYTE
    MAIN_SECRET as STRING*32
    ' Checksum of main_secret against memory corruption for any reason
    MAIN_SECRET_SHA1 as STRING*20
END TYPE
PUBLIC __LCK_MAIN_STATUS as TYPE_LCK_STATUS = 0, "", ""




' Function: LCK_INITIALIZED
' -------------------------
' Returns if LCK subsystem is initialized.
FUNCTION LCK_INITIALIZED() AS BYTE
    LCK_INITIALIZED = asc(LCK_MAIN_SECRET_ENCRYPTED(1))
END FUNCTION



' Subroutine: LCK_LOCKUP
' -----------------------
' Clear the memory and lock up this subsystem again.
SUB LCK_LOCKUP()
    __LCK_MAIN_STATUS.MAIN_SECRET_SHA1 = ""
    __LCK_MAIN_STATUS.MAIN_SECRET = crypto_random32bytes()
    __LCK_MAIN_STATUS.UNLOCKED = 0
END SUB



' Function: LCK_GET_KEY
' ---------------------
' Get a key for encrypting storage. This function can be only called when both
' the LCK and GRD subsystem are unlocked, and integrity of memorised main key
' can be validate. Returns "" otherwise.
FUNCTION LCK_GET_KEY() as STRING
    IF __LCK_MAIN_STATUS.UNLOCKED <> &HFF OR GRD_SESSION_ACTIVE() <> &HFF THEN
        LCK_GET_KEY = ""
        EXIT FUNCTION
    END IF
    IF &H00 = strcmp_64(_ 
        __LCK_MAIN_STATUS.MAIN_SECRET_SHA1,_ 
        ShaHash(__LCK_MAIN_STATUS.MAIN_SECRET)_ 
    ) THEN
        LCK_GET_KEY = ""
        EXIT FUNCTION
    END IF
    LCK_GET_KEY = __LCK_MAIN_STATUS.MAIN_SECRET        
END FUNCTION




' Subroutine: LCK_INITIALIZE
' --------------------------
' Sets up the private secret. A new main_secret is generated, making all
' previously encrypted storaged data unusable. The user key is set to default
' being 32 bytes of 0x00.
'
' The LCK subsystem is UNLOCKED after calling initialized.
SUB LCK_INITIALIZE()
    PRIVATE main_secret as STRING*32
    main_secret = crypto_random32bytes()
    
    PRIVATE main_secret_encrypted as STRING
    main_secret_encrypted = crypto_encrypt(LCK_DEFAULT_USERKEY, main_secret)
    
    LCK_MAIN_SECRET_ENCRYPTED = chr$(&HFF) +_
        main_secret_encrypted + main_secret_encrypted + main_secret_encrypted
        
    __LCK_MAIN_STATUS.MAIN_SECRET = main_secret
    __LCK_MAIN_STATUS.MAIN_SECRET_SHA1 = ShaHash(main_secret)
    __LCK_MAIN_STATUS.UNLOCKED = &HFF
END SUB



' Command: LCK_UNLOCK
' -------------------
' Unlocks the main encryption key using a user input.
COMMAND &H02 &H00 LCK_UNLOCK(data as STRING)
    ' If GRD subsystem not initialized: break
    IF GRD_SESSION_ACTIVE() <> &HFF THEN
        data = GRD_RESPONSE(S_ERROR, "UNAUTHORIZED", 0)
        EXIT COMMAND
    END IF

    ' Do nothing if already unlocked
    IF __LCK_MAIN_STATUS.UNLOCKED = &HFF THEN
        data = GRD_RESPONSE(S_OK, "OK", GRD_OPTION_CREDENTIAL)
        EXIT COMMAND
    END IF

    IF &H00 = LCK_INITIALIZED() THEN
        call LCK_INITIALIZE()
        data = GRD_RESPONSE(S_OK, "OK, DEFAULT", GRD_OPTION_CREDENTIAL)
        EXIT COMMAND
    END IF
    
    PRIVATE decrypt_key as STRING
    decrypt_key = GRD_DECRYPT(data)
    IF decrypt_key = "" THEN
        data = GRD_RESPONSE(S_ERROR, "UNAUTHORIZED", 0)
        EXIT COMMAND
    END IF
    
    PRIVATE main_secret as STRING
    main_secret = Right$(LCK_MAIN_SECRET_ENCRYPTED, 3*(32+CRYPTO_OVERHEAD))
    main_secret = resume_triplestr(main_secret, 32+CRYPTO_OVERHEAD)
    main_secret = crypto_decrypt(decrypt_key, main_secret)
    
    IF main_secret = "" THEN
        data = GRD_RESPONSE(S_ERROR, "FAILED", GRD_OPTION_CREDENTIAL)
        call GRD_SESSION_RESET()
        EXIT COMMAND
    END IF

    __LCK_MAIN_STATUS.MAIN_SECRET = main_secret
    __LCK_MAIN_STATUS.MAIN_SECRET_SHA1 = ShaHash(main_secret)
    __LCK_MAIN_STATUS.UNLOCKED = &HFF
    data = GRD_RESPONSE(S_OK, "OK", GRD_OPTION_CREDENTIAL)
END COMMAND



' Command: LCK_LOCK
' -------------------
' Set the status to be locked.
COMMAND &H02 &H02 LCK_LOCK(data as STRING)
    ' If GRD subsystem not initialized: break
    IF GRD_SESSION_ACTIVE() <> &HFF THEN
        data = GRD_RESPONSE(S_ERROR, "UNAUTHORIZED", 0)
        EXIT COMMAND
    END IF
    call LCK_LOCKUP()
    data = GRD_RESPONSE(S_OK, "OK", 0)
END COMMAND



' Command: LCK_CHANGE_KEY
' -----------------------
' Use the new user-supplied key to encrypt the main key.
COMMAND &H02 &H04 LCK_CHANGE_KEY(data as string)
    PRIVATE main_secret as STRING
    main_secret = LCK_GET_KEY() ' a reliable main secret may be returned
    IF Len(main_secret) <> 32 THEN
        data = GRD_RESPONSE(S_ERROR,_
            "UNAUTHORIZED OR INTEGRITY ERROR", GRD_OPTION_CREDENTIAL)
        EXIT COMMAND
    END IF
    
    PRIVATE user_key as STRING
    user_key = GRD_DECRYPT(data)
    IF Len(user_key) <> 32 THEN
        data = GRD_RESPONSE(S_ERROR, "FAILED", GRD_OPTION_CREDENTIAL)
        EXIT COMMAND
    END IF
    
    PRIVATE main_secret_encrypted as STRING
    main_secret_encrypted = crypto_encrypt(user_key, main_secret)
    LCK_MAIN_SECRET_ENCRYPTED = chr$(&HFF) +_
        main_secret_encrypted + main_secret_encrypted + main_secret_encrypted    

    call LCK_LOCKUP()
    data = GRD_RESPONSE(S_OK, "OK", 0)
END COMMAND
