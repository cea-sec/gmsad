#!/usr/bin/env python3

from gmsad.keytab import Keytab, KeytabEntry, Keyblock
from gmsad.enctypes import RFC_AES128_CTS_HMAC_SHA1_96, RFC_AES256_CTS_HMAC_SHA1_96
import argparse
import sys
import logging


def __main__():
    parser = argparse.ArgumentParser(
            formatter_class=argparse.RawDescriptionHelpFormatter,
            description="Generates a keytab file, given the account keys (aes128 or aes256)")
    parser.add_argument("-v", "--verbose", action="store_true")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--aes256", action="store_true", help="aes256 key")
    group.add_argument("--aes128", action="store_true", help="aes128 key")

    parser.add_argument("name", help="With the ending dollar if its a machine account")
    parser.add_argument("realm")
    parser.add_argument("keytab", help="Output keytab file")
    parser.add_argument("key", help="Hex string of the key")
    args = parser.parse_args()

    if args.verbose:
        logging.basicConfig(level="DEBUG")

    key = bytes.fromhex(args.key)
    if args.aes128:
        block = Keyblock(RFC_AES128_CTS_HMAC_SHA1_96, key)
    elif args.aes256:
        block = Keyblock(RFC_AES256_CTS_HMAC_SHA1_96, key)

    entry = KeytabEntry(f"{args.name}@{args.realm}", 1, 0, block)
    keytab = Keytab()
    keytab.entries.append(entry)
    keytab.write(args.keytab)

    return 0

if __name__ == "__main__":
    sys.exit(__main__())
