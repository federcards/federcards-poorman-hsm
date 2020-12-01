#include SHA.DEF


PUBLIC UTIL_RANDOM_POOL as string*254

FUNCTION random_bytes_max_128(ByVal length as BYTE) as STRING
    IF length >= 128 THEN
        length = 128
    END IF

    PRIVATE chunk as STRING*4
    PRIVATE i_max as BYTE
    PRIVATE i as BYTE

    i_max = length / 4 + 1

    FOR i=0 TO i_max
        chunk as Long = Rnd
        random_bytes_max_128 = random_bytes_max_128 + chunk
    NEXT

    random_bytes_max_128 = Left$(random_bytes_max_128, length)
	
END FUNCTION