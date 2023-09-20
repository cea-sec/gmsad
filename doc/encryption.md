# Encryption Mechanisms

To retrieve the gMSA password, i.e. query `msDS-ManagedPassword`, the LDAP connection must provide confidentiality. This can be provided using:
* GSSAPI privacy (`kerberos`)
* TLS (`tls`)

`gmsad` relies on `ldap3` to implement these mechanisms :
- `tls` is supported out of the box.
- `kerberos` is not officially supported by ldap3, but there is a pull request that implements it: https://github.com/cannatag/ldap3/pull/1042.

By default, gmsad will try to use `kerberos` and fallback to `tls` if it fails (for example if your version of ldap3 does not support Kerberos encryption).
