#!/usr/bin/env python3

import argparse
import sys
import logging
import getpass
import binascii

from gmsad.enctypes import aes256_cts_hmac_sha1_96_string_to_key, aes128_cts_hmac_sha1_96_string_to_key
from gmsad.salt import get_salt_from_preauth
from gmsad.utils import get_dc


def __main__():
    parser = argparse.ArgumentParser(
            formatter_class=argparse.RawDescriptionHelpFormatter,
            description="Calculate AES keys for a given password")
    parser.add_argument("-v", "--verbose", action="store_true")
    group_password = parser.add_mutually_exclusive_group()
    group_password.add_argument("--password", help="Plain text password. If not given, will be retrieved with getpass()")
    group_password.add_argument("--password-hex", help="Password in hex. Useful if the password contains non printable characters")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--salt", help="Salt used for key calculation. If not given, will be retrieve using <principal> argument")
    group.add_argument("--principal", help="Kerberos principal <principal@realm>. Used to retrieve salt")
    args = parser.parse_args()

    if args.verbose:
        logging.basicConfig(level="DEBUG")
    
    if args.password:
        password = args.password
    elif args.password_hex:
        password = binascii.unhexlify(args.password_hex)\
            .decode('utf-16le', 'replace')\
            .encode('utf-8')
    else:
        password = getpass.getpass()

    if args.salt:
        salt = args.salt
    else:
       principal, realm = args.principal.split('@')
       dc = get_dc(realm)
       salt = get_salt_from_preauth(dc, principal, realm.upper())

    if args.verbose:
        print(f"salt: {salt}")

    aes256_key = aes256_cts_hmac_sha1_96_string_to_key(password, salt.encode('utf-8'))
    aes128_key = aes128_cts_hmac_sha1_96_string_to_key(password, salt.encode('utf-8'))

    print(f"AES256: {aes256_key.hex()}")
    print(f"AES128: {aes128_key.hex()}")

    return 0

if __name__ == "__main__":
    sys.exit(__main__())
