' HMAC slots subsystem
' --------------------
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

