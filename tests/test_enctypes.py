import unittest

from gmsad.enctypes import aes128_cts_hmac_sha1_96_string_to_key, \
        aes256_cts_hmac_sha1_96_string_to_key

class TestEnctypes(unittest.TestCase):
    """
    This tests the two hashing algorithms supported by gmsad:
    aes128_cts_hmac_sha1_96 and aes256_cts_hmac_sha1_96
    """

    def test_aes128_sha1(self):
        password = "tutu1234".encode('utf-8')
        salt = "WINDOMAIN.LOCALtest_machine".encode('utf-8')
        expected = bytes([176, 125, 7, 74, 140, 17, 251, 194, 222, 130, 96,
            148, 78, 168, 169, 242])
        self.assertEqual(
                aes128_cts_hmac_sha1_96_string_to_key(password, salt),
                expected)

    def test_aes256_sha1(self):
        password = "tutu1234".encode('utf-8')
        salt = "WINDOMAIN.LOCALtest_machine".encode('utf-8')
        expected = bytes([113, 254, 172, 99, 210, 210, 80, 127, 228, 42, 50,
            70, 12, 182, 223, 35, 104, 111, 204, 66, 107, 192, 29, 24, 33,
            182, 239, 87, 115, 88, 24, 82])
        self.assertEqual(
                aes256_cts_hmac_sha1_96_string_to_key(password, salt),
                expected)

    # The following known-answer vectors use the sample inputs of RFC 3962
    # appendix B, but with the default iteration count of 4096 (RFC 3962 does
    # not publish vectors for 4096 iterations). The expected values were
    # generated with the previous pycryptodomex-based implementation of these
    # functions to guarantee byte-identical output.

    def test_aes128_sha1_rfc3962_inputs(self):
        password = "password".encode('utf-8')
        salt = "ATHENA.MIT.EDUraeburn".encode('utf-8')
        expected = bytes([252, 168, 34, 149, 24, 19, 251, 37, 33, 84, 200,
            131, 245, 238, 28, 244])
        self.assertEqual(
                aes128_cts_hmac_sha1_96_string_to_key(password, salt),
                expected)

    def test_aes256_sha1_rfc3962_inputs(self):
        password = "password".encode('utf-8')
        salt = "ATHENA.MIT.EDUraeburn".encode('utf-8')
        expected = bytes([1, 184, 151, 18, 29, 147, 58, 180, 75, 71, 235, 84,
            148, 219, 21, 229, 14, 183, 69, 48, 219, 218, 233, 182, 52, 214,
            80, 32, 255, 93, 136, 193])
        self.assertEqual(
                aes256_cts_hmac_sha1_96_string_to_key(password, salt),
                expected)
