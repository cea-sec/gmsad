import unittest
import time
import tempfile

from gmsad.keytab import Keytab, InvalidPrincipal

FEEDS = [
    {
        "princ": "user@REALM",
        "realm": "REALM",
        "components": ["user"],
        "salt": "REALMuser.realm",
        "kvno": 1,
        "password": "toto".encode('utf-8'),
        "enctypes": 0x18 # Will result in 2 entries with enctypes 17 and 18
    },
    {
        "princ": "tutu@REALM",
        "realm": "REALM",
        "components": ["tutu"],
        "salt": "REALMtutu.realm",
        "kvno": 512,
        "password": "tutu".encode('utf-8'),
        "enctypes": 0x10 # One entry with enctype 18
    },
    {
        "princ": "http/tutu@REALM",
        "realm": "REALM",
        "components": ["http", "tutu"],
        "salt": "REALMhttptutu.realm",
        "kvno": 10,
        "password": "httptutu".encode('utf-8'),
        "enctypes": 0x8 # One entry with enctype 17
    },
]

class TestKeytab(unittest.TestCase):

    def setUp(self):
        self.tmpfile = tempfile.NamedTemporaryFile()

    # Test helpers

    def populate_keytab(self, keytab):
        for elt in FEEDS:
            keytab.add_entry(elt['princ'], elt['salt'], elt['kvno'],
                    elt['password'], elt['enctypes'])

    def find_princ(self, keytab, princ):
        for entry in keytab.entries:
            if entry.principal == princ:
                yield entry


    def check_feed_keytab(self, keytab):
        self.assertTrue(keytab.have_content())

        # Introspect keytab: may fail if Keytab class structure changes
        self.assertEqual(len(keytab.entries), 4)

        for feed in FEEDS:
            entries = self.find_princ(keytab, feed["princ"])
            for entry in entries:
                self.assertEqual(entry.principal, feed["princ"])
                self.assertEqual(entry.realm, feed["realm"])
                self.assertEqual(entry.components, feed["components"])
                self.assertTrue(entry.timestamp <= time.time())
                self.assertEqual(entry.vno, feed["kvno"])

        user_entries = list(self.find_princ(keytab, "user@REALM"))
        self.assertEqual(len(user_entries), 2)
        user_enctypes = (user_entries[0].key.type, user_entries[1].key.type)
        self.assertIn(17, user_enctypes)
        self.assertIn(18, user_enctypes)

    # Real tests

    def test_empty_keytab(self):
       keytab = Keytab()
       self.assertFalse(keytab.have_content())

       keytab.open(self.tmpfile.name)
       self.assertFalse(keytab.have_content())

    def test_keytab_creation(self):
        keytab = Keytab()
        self.populate_keytab(keytab)
        self.check_feed_keytab(keytab)

    def test_remove_entries(self):
        keytab = Keytab()
        self.populate_keytab(keytab)

        self.assertTrue(keytab.have_content())

        for feed in FEEDS:
            keytab.remove_entries(feed["princ"])

        self.assertFalse(keytab.have_content())

    def test_write_read_keytab(self):
        keytab = Keytab()
        self.populate_keytab(keytab)
        keytab.write(self.tmpfile.name)

        # Check file existence
        with open(self.tmpfile.name, 'r+b'):
            pass

        new_keytab = Keytab()
        new_keytab.open(self.tmpfile.name)
        self.check_feed_keytab(new_keytab)

    def test_bad_princ(self):
        keytab = Keytab()
        with self.assertRaises(InvalidPrincipal):
            keytab.add_entry("toto", "salt", "1", "toto".encode('utf-8'), 0x8)
