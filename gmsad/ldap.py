import configparser
import logging
import ssl
from typing import List, Any

import ldap3

from gmsad.utils import get_dc

class LDAPConnection:
    server: ldap3.Server
    connection: ldap3.Connection

    def __init__(self, config: configparser.SectionProxy) -> None:
        self.config = config
        # GSSAPI privacy is not supported by ldap3, so TLS is mandatory
        # If <ca_certs_file> is not set, the system wide installed certificates
        # are used.
        tls = ldap3.Tls(
                validate=ssl.CERT_REQUIRED,
                version=ssl.PROTOCOL_TLSv1_2,
                ca_certs_file=self.config.get("tls_ca_certs_file", fallback=None),
                valid_names=self.config.getlist("tls_valid_names", fallback=None),
        )

        if "host" in self.config:
            host = self.config["host"]
        else:
            host = get_dc(self.config['gMSA_domain'])
        logging.debug("LDAP Server host to contact is %s", host)
        
        auto_bind = ldap3.AUTO_BIND_NO_TLS
        # Auto bind explicitly set in the configuration
        if "ldap_auto_bind" in self.config:
            auto_bind = self.config.get("ldap_auto_bind").upper()
            # Allow to write 'AUTO_BIND_NONE' or just 'NONE'
            if not auto_bind.startswith("AUTO_BIND_"):
                auto_bind = f"AUTO_BIND_{auto_bind}"
            if not hasattr(ldap3, auto_bind):
                raise ValueError(f"Ldap Auto bind value {auto_bind} is invalid. See https://ldap3.readthedocs.io/en/latest/connection.html for the valid auto_bind values.")
            else:
                auto_bind = getattr(ldap3, auto_bind)


        self.server = ldap3.Server(host, get_info=ldap3.ALL, tls=tls)
        self.connection = ldap3.Connection(
                self.server,
                user=self.config["principal"],
                authentication=ldap3.SASL,
                sasl_mechanism=ldap3.KERBEROS,
                auto_bind=auto_bind,
                cred_store={'client_keytab': self.config["keytab"]})
        self.connection.start_tls()

        try:
            logging.debug("Authenticated as %s", self.connection.extend.standard.who_am_i())
        except ldap3.core.exceptions.LDAPExtensionError as e:
            if str(e) != "extension not in DSA list of supported extensions":
                raise e
            logging.debug("Authenticated as ??? (WhoAmI extension is not supported by the ldap server)")

    def get_gmsa_attributes(self, attributes: List[str]) -> Any:
        """
        Retrieve the given <attributes> list of the gMSA account.
        :return a dict like object (see ldap3 documentation)
        """
        ldap_filter = "(&(ObjectClass=msDS-GroupManagedServiceAccount)"\
                      "(sAMAccountName=%s))" % self.config["gMSA_sAMAccountName"]
        logging.debug("Execute ldap search query with filter \"%s\" "\
                      "and retrieve attributes %s", ldap_filter, attributes)
        success = self.connection.search(
                self.server.info.other["rootDomainNamingContext"][0],
                ldap_filter,
                search_scope=ldap3.SUBTREE,
                attributes=attributes)

        if not success:
            raise ValueError(
                    "Could not find gMSA account %s in LDAP" % self.config["gMSA_sAMAccountName"])
        if len(self.connection.entries) == 1:
            return self.connection.entries[0]
        elif len(self.connection.entries) == 0:
            raise ValueError(
                    "Could not find gMSA account %s in LDAP" % self.config["gMSA_sAMAccountName"])
        else:
            raise ValueError(
                    "This is not supposed to happen, found too many gMSA accounts named %s in LDAP"
                    % self.config["gMSA_sAMAccountName"])

    def close(self) -> None:
        self.connection.unbind()
