# gmsad

`gmsad` manages Active Directory group Managed Service Account (gMSA) on Linux.

Given the keytab of an account which has the ability to retrieve the secret of a gMSA, `gmsad` creates a keytab for the service account and renew it when necessary. It can execute an arbitrary command just after renewing the keytab.

# Requirements

Your Active Directory domain must be able to use group Managed Service Account which implies :
* AD schema updated to Windows Server 2012 ([Getting Started with Group Managed Service Accounts](https://learn.microsoft.com/en-us/windows-server/security/group-managed-service-accounts/getting-started-with-group-managed-service-accounts))
* KDS Root Key deployed ([Create the Key Distribution Services KDS Root Key](https://learn.microsoft.com/en-us/windows-server/security/group-managed-service-accounts/create-the-key-distribution-services-kds-root-key))

In addition, `gmsad` requires a working LDAPS interface on domain controllers with a valid TLS certificate.

# Documentation

- [Getting started with gmsad](doc/getting_started.md)
- [Why was this tool created ?](doc/genesis.md)
- [How does a gMSA work ?](doc/gmsa.md)
- [Talk at SSTIC 2023 (in french)](https://www.sstic.org/2023/presentation/gmsad/)

# Contributing

Any contribution is welcome, be it code, bug report, packaging, documentation or translation.

# License

gmsad is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

gmsad is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with gmsad. If not, see the gnu.org web site.
