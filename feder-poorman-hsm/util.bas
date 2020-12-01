#include SHA.DEF


PUBLIC UTIL_RANDOM_POOL as string*254

FUNCTION random_bytes_max_128(ByVal length as BYTE) as STRING
	if length >= 128 then
		length = 128
	end if

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