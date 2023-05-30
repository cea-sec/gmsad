"""
aes128-cts-hmac-sha1-96 and aes256-cts-hmac-sha1-96 implementation as described
in RFC 3961 and RFC 3962.
"""
import typing

from Cryptodome.Cipher import AES
from Cryptodome.Protocol import KDF


# Constants retrieved from examples of annexe A.1 in RFC 3961
#      128-fold("kerberos") =
#               6b657262 65726f73 7b9b5b2b 93132b93
# Those constants should be calculated using the nfold function (defined in
# section 5.1) on the string "kerberos".
AES_CONSTANT_128_FOLD = [0x6B,0x65,0x72,0x62,0x65,0x72,0x6F,0x73,0x7B,0x9B,0x5B,0x2B,0x93,0x13,0x2B,0x93]
# AES_CONSTANT_256_FOLD is not needed. AES256 uses a 256 bits key but encrypts 128
# bits data blocks (see NIST FIPS 197).

# See RFC 3961 section 5.3:
# initial cipher state      All bits zero
IV = [0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00]

# See RFC 3962 : "default string-to-key parameters        00 00 10 00"
ITERATION = 4096

MS_AES128_CTS_HMAC_SHA1_96 = 0x08
MS_AES256_CTS_HMAC_SHA1_96 = 0x10

RFC_AES128_CTS_HMAC_SHA1_96 = 17
RFC_AES256_CTS_HMAC_SHA1_96 = 18


def aes128_cts_hmac_sha1_96_string_to_key(password: bytes, salt: bytes) -> bytes:
    """string_to_key function for aes128_cts_hmac_sha1_96
    Defined in RFC 3962 section 4"""
    key_size = 16 # 128 bits key for AES128 (see NIST FIPS 197)
    # Password cast in str is required for mypy type checking
    # but PBKDF2 accept bytes input
    aes_128_key = KDF.PBKDF2(typing.cast(str, password), salt, key_size, ITERATION)
    cipher = AES.new(aes_128_key, AES.MODE_CBC, bytes(IV))
    return cipher.encrypt(bytes(AES_CONSTANT_128_FOLD))


def aes256_cts_hmac_sha1_96_string_to_key(password: bytes, salt: bytes) -> bytes:
    """string_to_key cuntion from aes256_cts_hmac_sha1_96
    Defined in RFC 3962 section 4

    Double encryption and concatenation is explained in RFC 3961 section 5.1:

        If the output of E is shorter than k bits, it is fed back into the
        encryption as many times as necessary.  The construct is as follows (where
        | indicates concatentation):

          K1 = E(Key, n-fold(Constant), initial-cipher-state)
          K2 = E(Key, K1, initial-cipher-state)
          K3 = E(Key, K2, initial-cipher-state)
          K4 = ...

          DR(Key, Constant) = k-truncate(K1 | K2 | K3 | K4 ...)
    """
    key_size = 32 # 256 bits key for AES256 (see NIST FIPS 197)
    # password cast in str is required for mypy type checking
    # but PBKDF2 accept bytes input
    aes_256_key = KDF.PBKDF2(typing.cast(str, password), salt, key_size, ITERATION)

    cipher = AES.new(aes_256_key, AES.MODE_CBC, bytes(IV))
    k1 = cipher.encrypt(bytes(AES_CONSTANT_128_FOLD))

    cipher = AES.new(aes_256_key, AES.MODE_CBC, bytes(IV))
    k2 = cipher.encrypt(bytearray(k1))

    return k1 + k2


ENCTYPES = {
    RFC_AES128_CTS_HMAC_SHA1_96: aes128_cts_hmac_sha1_96_string_to_key,
    RFC_AES256_CTS_HMAC_SHA1_96: aes256_cts_hmac_sha1_96_string_to_key
}


MS_ENCTYPES_TO_RFC = {
    MS_AES128_CTS_HMAC_SHA1_96: RFC_AES128_CTS_HMAC_SHA1_96,
    MS_AES256_CTS_HMAC_SHA1_96: RFC_AES256_CTS_HMAC_SHA1_96
}
