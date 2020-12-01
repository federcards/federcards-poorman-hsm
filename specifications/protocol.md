Feder Card / Poorman HSM Specfication
=====================================

A Poorman's HSM is a Feder card that provides basic cryptographic functions on
a secured element. Following features are designed:

1. Always shared-secret authenticated communication. The first thing you need
to do with a federcard is authenticating yourself and establishing a temporary
session key with this card. All commands and results are encrypted via this
session key, preventing potential insecurity on circuit or cable.




## 1. Protocol

### 1.1 Authentication

Authentication and establishing a session key is based on a sharedsecret.

Denotation: AES(plaintext, key)

1. Before this procedure, the card and the user shares a secret, `SS`, via card
initialization command (e.g. **CMD_FACTORY_RESET**).
2. Upon reset, the card generates a 16 byte random seed `RC` for
authentication.
3. The user retrieves `AES(RC, SS)`, a encrypted version of `RC` using the
sharedsecret, using command **CMD_PREAUTH**.
4. The user decrypts this info and gets `RC` by using its sharedsecret.
4. The user selects 20 bytes of random bytes `RU`, such that `SHA1(RU | RC | SS)`
have at least 22 leading bits being 0. This is called hashcash, a process
making user authentication more time consuming. The number 22 is a requirement
by card and may change under some conditions.
5. The user authenciates itself with the card sending `AES(RU, RC | SS)` and
`SHA1(RU | RC | SS)` via command **CMD_AUTH**. The card confirms this by first
decrypting `RU` and then validating the SHA1 hash. If the SHA1 hash cannot be
verified, a failed authentication occurs, where the card may decrease its
lockdown counter.
6. Now the key (RU | RC | SS) is the key used for secure messaging.


### 1.2 Federcard customized secure messaging

Payload plaintext:    | Opcode(2-bytes) | Payload |

Payload encrypted with AES-CTR mode. Nonce 15 bytes. MAC 16 bytes on plaintext.

Payload plaintext max length: 220 bytes. 




## 2. Commands (CLA, INS)

### (0x88, 0x00): CMD\_PREAUTH

### (0x88, 0x02): CMD\_AUTH

### (0x88, 0x88): CMD\_FACTORY\_RESET
