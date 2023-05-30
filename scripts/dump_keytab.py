#!/usr/bin/env python3

from gmsad.keytab import Keytab
import textwrap
import argparse
import sys

enctypes = {
    1: "des-cbc-crc (weak)",
    2: "des-cbc-md4 (weak)",
    3: "des-cbc-md5 (weak)",
    4: "des-cbc-raw (weak)",
    6: "des3-cbc-raw (weak)",
    16: "des3-cbc-sha1",
    17: "aes128-cts-hmac-sha1-96",
    18: "aes256-cts-hmac-sha1-96",
    19: "aes128-cts-hmac-sha256-128",
    20: "aes256-cts-hmac-sha384-192",
    23: "arcfour-hmac",
    24: "arcfour-hmac-exp (weak)",
    25: "camellia128-cts-cmac",
    26: "camellia256-cts-cmac",
}

def __main__():
    parser = argparse.ArgumentParser(
            formatter_class=argparse.RawDescriptionHelpFormatter,
            description=textwrap.dedent("""\
                    Parse a keytab file and print its entries,
                    including hex encoded keys.
                    Format: <kvno>:<principal>:<enctype>:<key>
                    """)
            )
    parser.add_argument("keytab", help="Keytab file")
    args = parser.parse_args()

    try:
        with open(args.keytab, "rb"):
            pass
    except Exception as e:
        print(f"Failed to open keytab file: {e}", file=sys.stderr)
        return 1

    keytab = Keytab()
    keytab.open(args.keytab)

    for entry in keytab.entries:
        principal = '/'.join(entry.components)
        print(f"{entry.vno}:{principal}@{entry.realm}:{enctypes[entry.key.type]}:{entry.key.key.hex()}")
    return 0

if __name__ == "__main__":
    sys.exit(__main__())
