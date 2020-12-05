Rem BasicCard Sample Source Code Template
Rem ------------------------------------------------------------------
Rem Copyright (C) 2008 ZeitControl GmbH
Rem You have a royalty-free right to use, modify, reproduce and 
Rem distribute the Sample Application Files (and/or any modified 
Rem version) in any way you find useful, provided that you agree 
Rem that ZeitControl GmbH has no warranty, obligations or liability
Rem for any Sample Application Files.
Rem ------------------------------------------------------------------
Option Explicit

#include AES.def
#include SHA.def
#include Card.def
#Include COMMANDS.DEF
#Include COMMERR.DEF
#include MISC.DEF
#Include CARDUTIL.DEF


#include util.bas





const HEX_ALPHABET = "0123456789ABCDEF"

function str2hex(ByVal strInput as String) as String
    private i as integer
    private c as byte
    for i = 1 to len(strInput)
        c = asc(strInput(i))
        Str2Hex = Str2Hex + HEX_ALPHABET(1+(c/16)) + HEX_ALPHABET(1+(c mod 16))
    next
end function

function _char2hex(byval c as string*1) as integer
    private x as byte
    x = asc(c)
    if x >= 48 and x <= 57 then
        _char2hex = x - 48      ' 0 - 9
    else if x >= 65 and x <= 70 then
        _char2hex = x - 65 + 10 ' A B C D E F
    else if x >= 97 and x <= 102 then
        _char2hex = x - 97 + 10 ' a b c d e f
    else
        _char2hex = -1
    end if    
end function




'  Execution starts here




' Wait for a card
Call WaitForCard()
' Reset the card and check status code SW1SW2
ResetCard : Call CheckSW1SW2()

Public Data$






Call GRD_GETINFO(Data$) : Call CheckSW1SW2()
print "INFO", str2hex(Data$)




public sharedsecret as string*32
public challenge as string
call GRD_PREAUTH(data$): call CheckSW1SW2()
challenge = data$
print "PREAUTH", str2hex(data$)
challenge = AES(-256, sharedsecret, challenge)

print "CHLNGE", str2hex(challenge)




public user_rand as string*16 = "deadbeefDEADBEEF"
public user_rand_encrypt_key as string*32
public sha1_session_key as string*20
public session_key as string*32

user_rand_encrypt_key = ShaHash(challenge + sharedsecret)

session_key = ShaHash(user_rand + challenge + sharedsecret)
sha1_session_key = ShaHash(session_key)

data$ = chr$(&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H00) + AES(256, user_rand_encrypt_key, user_rand) + sha1_session_key


call GRD_AUTH(data$) : call CheckSW1SW2()
print "AUTH-RET", data$



























