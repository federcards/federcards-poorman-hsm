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

#include Card.def
#Include COMMANDS.DEF
#Include COMMERR.DEF
#include MISC.DEF
#Include CARDUTIL.DEF


#include util.bas

'print strcmp_253("", "a")
'print strcmp_253("a", "a")
'print strcmp_253("a", "b")





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

' Test Hello World command
' A String variable to hold the response
Public Data$
' Call the command and check the status
Call GRD_GETINFO(Data$) : Call CheckSW1SW2()
' Output the result
print str2hex(Data$)

' Test to store some data
' Set the value to store
'Data$="I can keep this information"
' Call the command to write data and check the status
'Call WriteData(Data$) : Call CheckSW1SW2()
' Just for test change value of Data$
'Data$="You will not see this"
' Call the command to read back data and check the status
'Call ReadData(Data$) : Call CheckSW1SW2()
' Ouput the data
'print Data$

