#!/usr/bin/env python3

import math
import hashlib
import hmac
import os
from Crypto.Cipher import AES as OriginalAES


def ShaHash(msg):
    return hashlib.sha1(msg).digest()


def HMAC_SHA1(key, message):
    return hmac.HMAC(key, message, hashlib.sha1).digest()

def AES(mode, key, i_block):
    assert mode in [128, 192, 256, -128, -192, -256]
    assert len(i_block) == 16 and type(i_block) == bytes
    assert type(key) == bytes
    keylen = abs(mode) // 8
    key = key[:keylen]
    key = key.ljust(keylen, b"\x00")
    cipher = OriginalAES.new(key, OriginalAES.MODE_ECB)
    if mode > 0:
        return cipher.encrypt(i_block)
    else:
        return cipher.decrypt(i_block)


def crypto_ctr(k, iv, message):
    assert type(message) == bytes and len(message) <= 254

    blocksCount = math.ceil(len(message) / 16)
    iv0 = iv[:15]
    ivn = lambda n: iv0 + bytes([n])
    bytesStream = b"".join([
        AES(256, k, ivn(i)) for i in range(0, blocksCount)])

    output = bytes([
        message[i] ^ bytesStream[i] for i in range(0, len(message))])
    return output
    


def crypto_encrypt(encrypt_key, message):
    # Encrypts a string with length <= 256 bytes
    iv = os.urandom(15)
    tag = HMAC_SHA1(encrypt_key, message)[:10]
    ciphertext = crypto_ctr(encrypt_key, iv, message)
    return iv + tag + ciphertext 


def crypto_decrypt(decrypt_key, message):
    iv = message[:15]
    tag = message[15:][:10]
    ciphertext = message[25:]
    plaintext = crypto_ctr(decrypt_key, iv, ciphertext)
    if not HMAC_SHA1(decrypt_key, plaintext).startswith(tag):
        return None
    return plaintext
