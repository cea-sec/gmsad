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
        salt = "WINDOMAIN.LOCALtest_machine"
        expected = bytes([176, 125, 7, 74, 140, 17, 251, 194, 222, 130, 96,
            148, 78, 168, 169, 242])
        self.assertEqual(
                aes128_cts_hmac_sha1_96_string_to_key(password, salt),
                expected)

    def test_aes256_sha1(self):
        password = "tutu1234".encode('utf-8')
        salt = "WINDOMAIN.LOCALtest_machine"
        expected = bytes([113, 254, 172, 99, 210, 210, 80, 127, 228, 42, 50,
            70, 12, 182, 223, 35, 104, 111, 204, 66, 107, 192, 29, 24, 33,
            182, 239, 87, 115, 88, 24, 82])
        self.assertEqual(
                aes256_cts_hmac_sha1_96_string_to_key(password, salt),
                expected)
