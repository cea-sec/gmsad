import configparser
import logging
import ssl
from typing import List, Any, Tuple
import traceback

import ldap3

from gmsad.utils import get_dc

def setup_kerberos_connection(config: configparser.SectionProxy,
                              host: str) -> Tuple[ldap3.Server, ldap3.Connection]:
    try:
        from ldap3 import ENCRYPT
    except ImportError:
        raise Exception("ldap3 version does not support Kerberos encryption")

    server = ldap3.Server(host, get_info=ldap3.ALL)
    connection = ldap3.Connection(
            server,
            user=config["principal"],
            authentication=ldap3.SASL,
            sasl_mechanism=ldap3.KERBEROS,
            auto_bind=True,
            cred_store={'client_keytab': config["keytab"]},
            session_security=ldap3.ENCRYPT)
    return (server, connection)


def setup_tls_connection(config: configparser.SectionProxy,
                         host: str) -> Tuple[ldap3.Server, ldap3.Connection]:
    # If <ca_certs_file> is not set, the system wide installed certificates
    # are used.
    tls = ldap3.Tls(
        validate=ssl.CERT_REQUIRED,
        version=ssl.PROTOCOL_TLSv1_2,
        ca_certs_file=config.get("tls_ca_certs_file", fallback=None),
        valid_names=config.getlist("tls_valid_names", fallback=None),
    )

    server = ldap3.Server(host, get_info=ldap3.ALL, tls=tls)
    connection = ldap3.Connection(
            server,
            user=config["principal"],
            authentication=ldap3.SASL,
            sasl_mechanism=ldap3.KERBEROS,
            auto_bind=True,
            cred_store={'client_keytab': config["keytab"]})
    connection.start_tls()
    return (server, connection)


ENCRYPTION_MECHS = {
    'kerberos': setup_kerberos_connection,
    'tls': setup_tls_connection,
}


class LDAPConnection:
    server: ldap3.Server
    connection: ldap3.Connection

    def __init__(self, config: configparser.SectionProxy) -> None:
        self.config = config

        host = self.get_host()
        logging.debug("LDAP Server host to contact is %s", host)

        succeed = False
        for mech in config.get("encryption_mechs", fallback="kerberos,tls").lower().split(','):
            if not mech in ENCRYPTION_MECHS:
                raise ValueError(f"Unknown encryption mechanism '{mech}'")
            try:
                logging.debug("Setup a connection with '%s' encryption mechanism", mech)
                self.server, self.connection = ENCRYPTION_MECHS[mech](config, host)
                succeed = True
                break
            except Exception as e:
                logging.warning("Failed to setup '%s' encryption mechanism: %s", mech, e)
                logging.debug(traceback.format_exc())

        if not succeed:
            raise Exception("Could not setup a connection using specified mechanisms")

        logging.debug("Authenticated as %s", self.connection.extend.standard.who_am_i())

    def get_host(self) -> str:
        if "host" in self.config:
            return self.config["host"]
        else:
            return get_dc(self.config['gMSA_domain'])

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
                    "Could not find %s in LDAP" % self.config["gMSA_sAMAccountName"])
        assert len(self.connection.entries) == 1
        return self.connection.entries[0]

    def close(self) -> None:
        self.connection.unbind()
