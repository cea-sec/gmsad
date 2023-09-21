import configparser
import logging
import struct
import time
from datetime import datetime
import subprocess
import shlex
from typing import Optional, Tuple

from gmsad.ldap import LDAPConnection
from gmsad.keytab import Keytab
from gmsad.utils import get_dc
from gmsad.salt import get_salt_from_preauth, get_salt_from_heuristic


class GMSAState:
    config: configparser.SectionProxy
    current_password: bytes
    previous_password: bytes
    query_password_date: datetime
    unchanged_password_date: datetime
    keytab: Keytab

    def __init__(self, config: configparser.SectionProxy, keytab: Keytab) -> None:
        self.config = config
        self.current_password = bytes()
        self.previous_password = bytes()
        self.keytab = keytab
        self.query_password_date = datetime.fromtimestamp(0).astimezone()
        self.unchanged_password_date = datetime.fromtimestamp(0).astimezone()

    def needs_spn_update(self) -> bool:
        """
        Check if SPN keys need to be updated

        Between <unchanged_password_date> and <query_password_date>, the
        currentPassword returned is the next one but it is not yet usable.
        At <query_password_date>, the password of the gmsa is actually
        rotated.

        SPN keys need to be updated as soon as the new gMSA password is
        available (which occurs at <unchanged_password_date>). At this time,
        we can already add to the keytab the new keys while keeping the
        previous ones.

        :return True if an update is needed, False otherwise
        """
        if not "gMSA_servicePrincipalNames" in self.config:
            # No SPN configured
            return False

        if not self.keytab.have_content():
            # Keytab does not exist or is empty (at first use for example)
            return True

        if datetime.now().astimezone() > self.unchanged_password_date:
            # gMSA password will be able to rotate in next few minutes
            # New password is already available as current password
            return True

        # This can seem useless because we already got the new keys
        # after <unchanged_password_date>, BUT we need to trigger the
        # password change by calling <query_new_password>.
        if datetime.now().astimezone() > self.query_password_date:
            # gMSA password is ready to rotate
            return True

        return False

    def needs_upn_update(self) -> bool:
        """
        Check if UPN keys need to be updated

        In gmsad, a UPN (for User Principal Name) is a principal that can be used to
        authenticate (using `kinit`). UPN keys need to be updated in the
        keytab only when the gMSA password has rotated.

        Therefore, this function only checks if the gMSA password has rotated
        which occurs after <query_password_date>.

        :return True if an update is needed, False otherwise
        """
        if ("gMSA_servicePrincipalNames" in self.config
                and not self.config.getboolean("gMSA_upn_in_keytab", fallback=False)):
            # a SPN is configured and it is not explicitly asked
            # to put UPN in keytab
            return False

        if not self.keytab.have_content():
            # Keytab does not exist or is empty
            return True

        if datetime.now().astimezone() > self.query_password_date:
            # gMSA password has rotated
            return True

        return False

    def update(self) -> None:
        """
        Update the gMSA keytab with credentials retrieved from
        LDAP.

        It checks if a new password is available and if the keytab needs to be
        updated.

        If an update is necessary, it parses the msDS-ManagedPassword struct to
        retrieve current and previous password. It also computes the encryption
        algorithm used to generate key in the keytab according to the
        configuration and the supported encryption types of the gMSA.

        If everything goes well, it executes the rotate command (specified in
        the configuration) when the keytab is updated.
        """
        upn_update = self.needs_upn_update()
        spn_update = self.needs_spn_update()

        if not upn_update and not spn_update:
            # Nothing to do
            return

        kvno, enctypes = self.query_new_password()

        if upn_update:
            self.update_upn(kvno, enctypes)

        if spn_update:
            # Between unchanged_password_date and query_password_date, the kvno
            # has not been updated but the currentPassword returned is the new one.
            # For the generated keytab to be valid with implementations that check
            # the kvno value, the new password must be assigned to "kvno+1" and
            # the current to "kvno".
            # The kvno field will be incremented by AD at its effective
            # rotation, after query_password_date.
            if (datetime.now().astimezone() > self.unchanged_password_date
                    and datetime.now().astimezone() < self.query_password_date):
                kvno += 1
            self.update_spn(kvno, enctypes)


    def query_new_password(self) -> Tuple[int, int]:
        """
        Retrieve and parse MSDS-MANAGEDPASSWORD_BLOB struct

        Connects to a DC using LDAP and requests the msDS-ManagedPassword attribute.
        The first request after <query_password_date> triggers the gMSA password rotation.

        :return (kvno, enctypes) where:
        - kvno is the kvno of the currently valid password
        - enctypes is the encryption types that will be in keytab
        """
        logging.info("Retrieving secret of %s", self.config['gMSA_sAMAccountName'])
        ldap = LDAPConnection(self.config)

        # Retrieve the MSDS-MANAGEDPASSWORD_BLOB struct
        # It may trigger an update of the gmsa account kvno (and password).
        # This is what actually triggers the password rotation.
        # The "previous" password remains valid until the msDS-ManagedPassword
        # attribute is requested.
        attributes = ldap.get_gmsa_attributes([
            'msDS-ManagedPassword', # MSDS-MANAGEDPASSWORD_BLOB struct
            'msDS-SupportedEncryptionTypes', # Supported enctypes
        ])

        if len(attributes['msDS-ManagedPassword'].raw_values) == 0:
            raise ValueError(
                    "Could not retrieve msDS-ManagedPassword attribute of gMSA account %s in LDAP." \
                    " Does your account have sufficient permissions ?"
                    % self.config["gMSA_sAMAccountName"])

        password_blob = attributes['msDS-ManagedPassword'].raw_values[0]
        self.parse_managedpassword_blob(password_blob)

        enctypes = (self.config.getint("gMSA_enctypes", fallback=0x18)
                & attributes['msDS-SupportedEncryptionTypes'].value)
        logging.debug("Supported enctypes: %d, Wanted enctypes: %d, Sec entypes: %d",
                attributes['msDS-SupportedEncryptionTypes'].value,
                self.config.getint("gMSA_enctypes"),
                enctypes)

        if enctypes == 0:
            logging.warning("The requested encryption types (gMSA_enctypes=%d) are not"
                "supported by the gMSA (msDS-SupportedEncryptionTypes attribute value is %d)",
                self.config.getint("gMSA_enctypes"),
                attributes['msDS-SupportedEncryptionTypes'].value)

        # Retrieve new kvno
        # It must be done in a different LDAP query because the first
        # one may update the kvno (at least that what we experienced)
        kvno = ldap.get_gmsa_attributes(["msDS-KeyVersionNumber"])\
                ["msDS-KeyVersionNumber"].value

        ldap.close()

        return (kvno, enctypes)


    def write_keytab(self, princ: str, kvno: int, enctypes: int) -> None:
        """
        Write keytab entries for princ <princ> with kvno <kvno> and
        <kvno>-1 if it exists with keys of <enctypes>.
        It removes all previously existing keys corresponding to <princ>.
        """
        self.keytab.remove_entries(princ)

        # Retrieve salt
        config_salt = self.config.get("gMSA_salt", fallback=None)
        if config_salt is not None:
            logging.debug("Retrieving salt from configuration")
            salt = config_salt
        else:
            if self.config.getboolean("gMSA_salt_from_heuristic", fallback=False):
                logging.debug("Retrieving salt using an hardcoded heuristic")
                salt = get_salt_from_heuristic(self.config['gMSA_sAMAccountName'], self.config['gMSA_domain'])
            else:
                logging.debug("Retrieving salt by parsing a PRE-AUTH-REQUIRED response from DC")

                if "host" in self.config:
                    host = self.config["host"]
                else:
                    host = get_dc(self.config['gMSA_domain'])
                salt = get_salt_from_preauth(host, self.config['gMSA_sAMAccountName'], self.config['gMSA_domain'])

        # Write current password
        self.keytab.add_entry(
            princ = princ,
            salt = salt,
            kvno = kvno,
            password = self.current_password,
            enctypes = enctypes)

        # Write previous password if it exists
        if self.previous_password:
            self.keytab.add_entry(
                princ = princ,
                salt = salt,
                kvno = kvno - 1,
                password = self.previous_password,
                enctypes = enctypes)

        # Write changes
        self.keytab.write(self.config["gMSA_keytab"])


    def update_upn(self, kvno: int, enctypes: int) -> None:
        """
        Update the keytab entry corresponding to the
        User Principal Name of the gMSA
        """
        # sAMAccountName should end with a '$'
        princ = "{}@{}".format(
                self.config['gMSA_sAMAccountName'], self.config['gMSA_domain'])
        self.write_keytab(princ, kvno, enctypes)
        logging.info("Keytab entries for UPN %s have been updated successfully "
                     "(kvno = %d). Next update on %s",
                     princ, kvno, self.query_password_date.isoformat())
        self.run_on_rotate_cmd(self.config.get('on_upn_rotate_cmd', fallback=None))

    def update_spn(self, kvno: int, enctypes: int) -> None:
        """
        Update the keytab entries corresponding to the
        Service Principal Names of the gMSA
        """
        for spn in self.config.getlist('gMSA_servicePrincipalNames'):
            princ = "{}@{}".format(spn, self.config['gMSA_domain'])
            self.write_keytab(princ, kvno, enctypes)
            logging.info("Keytab entries for SPN %s have been updated successfully "
                        "(kvno = %d). Next update on %s",
                        princ, kvno, self.unchanged_password_date.isoformat())
        self.run_on_rotate_cmd(self.config.get('on_spn_rotate_cmd', fallback=None))

    def parse_managedpassword_blob(self, blob: bytes) -> None:
        """
        Parse a MSDS-MANAGEDPASSWORD_BLOB and populate class attributes

        See [MS-ADTS] 2.2.19
        """
        if len(blob) < 32:
            logging.error("MSDS-MANAGEDPASSWORD_BLOB structure received is invalid.")
            raise ValueError("MSDS-MANAGEDPASSWORD_BLOB structure received is invalid.")

        version = struct.unpack('<H', blob[0:2])[0]

        if version != 1:
            logging.error("MSDS-MANAGEDPASSWORD_BLOB structure version is not 1 "
                          "but %d", version)
            raise ValueError("MSDS-MANAGEDPASSWORD_BLOB structure version is invalid.")
        length = struct.unpack('<L', blob[4:8])[0]

        if length != len(blob):
            logging.error("MSDS-MANAGEDPASSWORD_BLOB structure length is "
                          "different than the number of received bytes "
                          "from LDAP (received: %d, expected: %d)",
                          len(blob), length)
            raise ValueError("MSDS-MANAGEDPASSWORD_BLOB structure length is invalid.")

        current_password_offset = struct.unpack('<H', blob[8:10])[0]
        previous_password_offset = struct.unpack('<H', blob[10:12])[0]
        query_password_interval_offset = struct.unpack('<H', blob[12:14])[0]
        unchanged_password_interval_offset = struct.unpack('<H', blob[14:16])[0]

        # Previous password is not always present, and in that case its offset is 0
        # (according to MS doc)
        end_current_password_offset = (
                query_password_interval_offset
                if previous_password_offset == 0
                else previous_password_offset)

        # Current password is a null-terminated WCHAR string containing the cleartext
        # current password of the account. We discard the 2 ending zeros of UTF16 encoding.
        # The cleartext password may contain invalid utf16 characters. We need to
        # replace these characters using Unicode replacement characters to be able
        # to use the password.
        self.current_password = \
                blob[current_password_offset:end_current_password_offset-2]\
                        .decode('utf-16le', 'replace')\
                        .encode('utf-8')

        if previous_password_offset != 0:
            self.previous_password = \
                    blob[previous_password_offset:query_password_interval_offset-2]\
                    .decode('utf-16le', 'replace')\
                    .encode('utf-8')

        # Query password interval is a 64-bit unsigned integer containing a
        # length of time, in units of 10^(-7) seconds.
        query_password_interval_raw = struct.unpack(
                '<Q',
                blob[query_password_interval_offset:query_password_interval_offset+8])
        # Query password interval is a number of seconds left before query password date.
        query_password_interval = query_password_interval_raw[0] / 1e7

        # Unchanged password interval is a 64-bit unsigned integer containing a
        # length of time, in units of 10^(-7) seconds.
        unchanged_password_interval_raw = struct.unpack(
                '<Q',
                blob[unchanged_password_interval_offset:unchanged_password_interval_offset+8])
        # Unchanged password interval is a number of seconds left before unchanged password
        # date.
        unchanged_password_interval = unchanged_password_interval_raw[0] / 1e7

        logging.debug("query_password_interval = %f", query_password_interval)
        logging.debug("unchanged_password_interval= %f", unchanged_password_interval)

        self.query_password_date = datetime.fromtimestamp(
                int(time.time() + query_password_interval)).astimezone()
        logging.debug("query_password_time: %s", self.query_password_date)

        self.unchanged_password_date = datetime.fromtimestamp(
                int(time.time() + unchanged_password_interval)).astimezone()
        logging.debug("unchanged_password_date: %s", self.unchanged_password_date)

    def run_on_rotate_cmd(self, command: Optional[str]) -> None:
        """
        Execute the on rotate command if it exists
        """
        if command is None:
            return
        logging.debug("Run on rotate command: %s", command)
        try:
            subprocess.run(shlex.split(command), check=True)
        except subprocess.CalledProcessError as e:
            logging.error("Rotate command failed: %s", e)
