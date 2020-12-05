' A constant time strcmp function, comparing string up to 253 bytes.

PUBLIC __strcmp_253_a AS STRING*254
PUBLIC __strcmp_253_b AS STRING*254
CONST __zero_254 = Chr$(0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0)

PUBLIC __strcmp_64_a AS STRING*65
PUBLIC __strcmp_64_b AS STRING*65


FUNCTION strcmp_253(a as STRING, b as STRING) as BYTE
    __strcmp_253_a = a + "!"
    __strcmp_253_b = b + "!"

    PRIVATE m as BYTE = 0
    PRIVATE i as BYTE
    FOR i = 1 TO 254
        m = m OR (Asc(__strcmp_253_a(i)) XOR Asc(__strcmp_253_b(i)))
    NEXT
    
    strcmp_253 = (0 = m)
    
    __strcmp_253_a = __zero_254
    __strcmp_253_b = __zero_254

END FUNCTION


FUNCTION strcmp_64(a as STRING, b as STRING) as BYTE
    __strcmp_64_a = a + "!"
    __strcmp_64_b = b + "!"

    PRIVATE m as BYTE = 0
    PRIVATE i as BYTE
    FOR i = 1 TO 65
        m = m OR (Asc(__strcmp_64_a(i)) XOR Asc(__strcmp_64_b(i)))
    NEXT
    
    strcmp_64 = (0 = m)
    
    __strcmp_64_a = Left$(__zero_254, 64)
    __strcmp_64_b = __strcmp_64_a

END FUNCTION