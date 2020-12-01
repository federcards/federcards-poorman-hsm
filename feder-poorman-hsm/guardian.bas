' Guardian Subsystem (GRD)
' ------------------------
' Defines commands for basic 

TYPE TYPE_GRD_STATUS
	CARD_SESSION_INITIALIZED as BYTE
	RAND_CARD as string*16
END TYPE
PUBLIC VAR_GRD_STATUS as TYPE_GRD_STATUS ' holder of card session status


EEPROM VAR_GRD_SHAREDSECRET as string


'-------------------------------------------------------------------------------
' Internal functions and subroutines

' Subroutine: GRD_SESSION_INIT
'
' Initialize the session, generates a new RAND_CARD, and marks
' CARD_SESSION_INITIALIZED = 1. 
SUB GRD_SESSION_INIT()
	VAR_GRD_STATUS.RAND_CARD = random_bytes_max_128(16)
END SUB


'-------------------------------------------------------------------------------
' Commands exposed


' Command: GRD_GETINFO
'
' Returns information on card status.
COMMAND &H00 &H00 GRD_GETINFO(LC=0, ret as STRING)
	ret = "OK"
END COMMAND

' Command: GRD_PREAUTH
'
' Called before a user attempts to authenticate itself with the card. Returns an
' encrypted value of RAND_CARD.
COMMAND &H00 &H02 GRD_PREAUTH(LC=0, ret as string)
END COMMAND

