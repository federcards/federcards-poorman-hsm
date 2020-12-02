' ******************************************************************************
' This file defines function
'  HMAC_SHA1(strKey, strMessage) as String
' which calculates a SHA1 based HMAC for given message.
' ******************************************************************************


const SHA1_BLOCK_SIZE = 64
const SHA1_OUTPUT_SIZE = 20

PUBLIC __HMAC_ZERO_64 as string*64 = Chr$(0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0)

PUBLIC __HMAC_SHA1_KEY AS STRING*64
PUBLIC __HMAC_I_PAD    AS STRING*64
PUBLIC __HMAC_O_PAD    AS STRING*64


Sub __HMAC_XOR64(ByRef src as STRING, ByRef dst as STRING, byteWith as Byte)
    private i as Integer
    for i = 1 to SHA1_BLOCK_SIZE
        dst(i) = chr$(asc(src(i)) xor byteWith)
    next
End Sub


Function HMAC_SHA1(strKey as String, strMessage as String) as String
    private o_key_pad as string
    private i_key_pad as string
    
    if len(strKey) > SHA1_BLOCK_SIZE then
        Left$(__HMAC_SHA1_KEY, SHA1_BLOCK_SIZE) = ShaHash(strKey)
    else
        Left$(__HMAC_SHA1_KEY, SHA1_BLOCK_SIZE) = strKey
    end if
    
    call __HMAC_XOR64(__HMAC_SHA1_KEY, __HMAC_I_PAD, &H36)
    call __HMAC_XOR64(__HMAC_SHA1_KEY, __HMAC_O_PAD, &H5C)
        
    HMAC_SHA1 = ShaHash(__HMAC_O_PAD + ShaHash(__HMAC_I_PAD + strMessage))
    
    __HMAC_O_PAD = __HMAC_ZERO_64
    __HMAC_I_PAD = __HMAC_ZERO_64
    __HMAC_SHA1_KEY = __HMAC_ZERO_64
End Function



