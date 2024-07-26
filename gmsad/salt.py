"""
Kerberos AS_REQ implementation used to retrieve the salt of a given principal.

A DC will respond to an AS_REQ without pre-authentication data with a
KRB_ERROR.  In this KRB_ERROR, of type KDC_ERR_PREAUTH_REQUIRED, we can find
the client salt within an ETYPE_INFO2 entry with
AES128_CTS_HMAC_SHA1_96_ENC type.

Note : this is will only work if the gMSA does not have the
DONT_REQUIRE_PREAUTH flags in its userAccountControl attribute. If this is
the case, the DC will respond with an AS_REP where we can also find the salt
within an ETYPE_INFO2 entry.

If this way of retrieving the salt fails, we suggest to use the
<gMSA_salt_from_heuristic> or <gMSA_salt> configuration parameter.

Useful documentation:
- RFC 4120: "The Kerberos Network Authentication Service (v5)"
- [MS-KILE]: Microsoft "Kerberos Network Authentication Service V5 Extensions"
"""

import struct
import random
import socket
from typing import Any as AnyType
from enum import IntEnum

from asn1crypto.core import Sequence, SequenceOf, Integer, BitString, OctetString, GeneralString, \
    GeneralizedTime, Any


APPLICATION_TAG = 1
AS_REQ_TAG_NUMBER = 10
AS_REP_TAG_NUMBER = 11
KRB_ERROR_TAG_NUMBER = 30

AS_MSG_TYPE = 10

NT_PRINCIPAL = 1
NT_SRV_INST = 2

PA_ETYPE_INFO2 = 19

AES128_CTS_HMAC_SHA1_96_ENC_TYPE = 17
AES256_CTS_HMAC_SHA1h96_ENC_TYPE = 18

TIME_T_ZERO = "19700101000000Z"

# UINT32_MAX_VAL = 0xFFFFFFFF
INT32_MAX_VAL = 0x7FFFFFFF

KERBEROS_PORT = 88

# From RFC 4120 section 7.5.9
class KRBErrorCode(IntEnum):
    KDC_ERR_NONE = 0
    KDC_ERR_NAME_EXP = 1
    KDC_ERR_SERVICE_EXP = 2
    KDC_ERR_BAD_PVNO = 3
    KDC_ERR_C_OLD_MAST_KVNO = 4
    KDC_ERR_S_OLD_MAST_KVNO = 5
    KDC_ERR_C_PRINCIPAL_UNKNOWN = 6
    KDC_ERR_S_PRINCIPAL_UNKNOWN = 7
    KDC_ERR_PRINCIPAL_NOT_UNIQUE = 8
    KDC_ERR_NULL_KEY = 9
    KDC_ERR_CANNOT_POSTDATE = 10
    KDC_ERR_NEVER_VALID = 11
    KDC_ERR_POLICY = 12
    KDC_ERR_BADOPTION = 13
    KDC_ERR_ETYPE_NOSUPP = 14
    KDC_ERR_SUMTYPE_NOSUPP = 15
    KDC_ERR_PADATA_TYPE_NOSUPP = 16
    KDC_ERR_TRTYPE_NOSUPP = 17
    KDC_ERR_CLIENT_REVOKED = 18
    KDC_ERR_SERVICE_REVOKED = 19
    KDC_ERR_TGT_REVOKED = 20
    KDC_ERR_CLIENT_NOTYET = 21
    KDC_ERR_SERVICE_NOTYET = 22
    KDC_ERR_KEY_EXPIRED = 23
    KDC_ERR_PREAUTH_FAILED = 24
    KDC_ERR_PREAUTH_REQUIRED = 25
    KDC_ERR_SERVER_NOMATCH = 26
    KDC_ERR_MUST_USE_USER2USER = 27
    KDC_ERR_PATH_NOT_ACCEPTED = 28
    KDC_ERR_SVC_UNAVAILABLE = 29
    KRB_AP_ERR_BAD_INTEGRITY = 31
    KRB_AP_ERR_TKT_EXPIRED = 32
    KRB_AP_ERR_TKT_NYV = 33
    KRB_AP_ERR_REPEAT = 34
    KRB_AP_ERR_NOT_US = 35
    KRB_AP_ERR_BADMATCH = 36
    KRB_AP_ERR_SKEW = 37
    KRB_AP_ERR_BADADDR = 38
    KRB_AP_ERR_BADVERSION = 39
    KRB_AP_ERR_MSG_TYPE = 40
    KRB_AP_ERR_MODIFIED = 41
    KRB_AP_ERR_BADORDER = 42
    KRB_AP_ERR_BADKEYVER = 44
    KRB_AP_ERR_NOKEY = 45
    KRB_AP_ERR_MUT_FAIL = 46
    KRB_AP_ERR_BADDIRECTION = 47
    KRB_AP_ERR_METHOD = 48
    KRB_AP_ERR_BADSEQ = 49
    KRB_AP_ERR_INAPP_CKSUM = 50
    KRB_AP_PATH_NOT_ACCEPTED = 51
    KRB_ERR_RESPONSE_TOO_BIG = 52
    KRB_ERR_GENERIC = 60
    KRB_ERR_FIELD_TOOLONG = 61
    KDC_ERROR_CLIENT_NOT_TRUSTED = 62
    KDC_ERROR_KDC_NOT_TRUSTED = 63
    KDC_ERROR_INVALID_SIG = 64
    KDC_ERR_KEY_TOO_WEAK = 65
    KDC_ERR_CERTIFICATE_MISMATCH = 66
    KRB_AP_ERR_NO_TGT = 67
    KDC_ERR_WRONG_REALM = 68
    KRB_AP_ERR_USER_TO_USER_REQUIRED = 69
    KDC_ERR_CANT_VERIFY_CERTIFICATE = 70
    KDC_ERR_INVALID_CERTIFICATE = 71
    KDC_ERR_REVOKED_CERTIFICATE = 72
    KDC_ERR_REVOCATION_STATUS_UNKNOWN = 73
    KDC_ERR_REVOCATION_STATUS_UNAVAILABLE = 74
    KDC_ERR_CLIENT_NAME_MISMATCH = 75
    KDC_ERR_KDC_NAME_MISMATCH = 76

class EncryptedData(Sequence):
    _fields = [
        ('etype', Integer, {'explicit': 0}),
        ('kvno', Integer, {'explicit': 1, 'optional': True}),
        ('cipher', OctetString, {'explicit': 2}),
    ]

class HostAddress(Sequence):
    _fields = [
        ('addr-type', Integer, {'explicit': 0}),
        ('address', OctetString, {'explicit': 1}),
    ]

class HostAddresses(SequenceOf):
    _child_spec = HostAddress

class Realm(GeneralString):
    pass

class KerberosString(GeneralString):
    pass

class KerberosStrings(SequenceOf):
    _child_spec = KerberosString

class PrincipalName(Sequence):
    _fields = [
        ('name-type', Integer, {'explicit': 0}),
        ('name-string', KerberosStrings, {'explicit': 1})
    ]

class KerberosFlags(BitString):
    pass

class KDCOptions(KerberosFlags):
    _map = {
        0: 'reserved',
        1: 'forwardable',
        2: 'forwarded',
        3: 'proxiable',
        4: 'proxy',
        5: 'allow-postdate',
        6: 'postdated',
        7: 'unused7',
        8: 'renewable',
        9: 'unused9',
        10: 'unused10',
        11: 'opt-hardware-auth',
        12: 'unused12',
        13: 'unused13',
        15: 'unused15',
        26: 'disable-transited-check',
        27: 'renewable-ok',
        28: 'enc-tkt-in-skey',
        30: 'renew',
        31: 'validate',
    }

class Integers(SequenceOf):
    _child_spec = Integer

class KerberosTime(GeneralizedTime):
    pass

class Ticket(Sequence):
    _fields = [
        ('tkt-vno', Integer, {'explicit': 0}),
        ('realm', Realm, {'explicit': 1}),
        ('sname', PrincipalName, {'explicit': 2}),
        ('enc-part', EncryptedData, {'explicit': 3}),
    ]

class Tickets(SequenceOf):
    _child_spec = Ticket

class KDC_REQ_BODY(Sequence):
    _fields = [
        ('kdc-options', KDCOptions, {'explicit': 0}),
        ('cname', PrincipalName, {'explicit': 1, 'optional': True}),
        ('realm', Realm, {'explicit': 2}),
        ('sname', PrincipalName, {'explicit': 3, 'optional': True}),
        ('from', KerberosTime, {'explicit': 4, 'optional': True}),
        ('till', KerberosTime, {'explicit': 5}),
        ('rtime', KerberosTime, {'explicit': 6, 'optional': True}),
        ('nonce', Integer, {'explicit': 7}),
        ('etype', Integers, {'explicit': 8, 'optional': True}),
        ('addresses', HostAddresses, {'explicit': 9, 'optional': True}),
        ('enc-authorization-data', EncryptedData, {'explicit': 10, 'optional': True}),
        ('additional-tickets', Tickets, {'explicit': 11, 'optional': True})
    ]

class PA_DATA(Sequence):
    _fields = [
        ('padata-type', Integer, {'explicit': 1}),
        ('padata-value', OctetString, {'explicit': 2})
    ]

class PA_DATA_SEQUENCE_OF(SequenceOf):
    _child_spec = PA_DATA

class KRB_KDC_REQ(Sequence):
    _fields = [
        ('pvno', Integer, {'explicit': 1}),
        ('msg-type', Integer, {'explicit': 2}),
        ('padata', PA_DATA_SEQUENCE_OF, {'explicit': 3, 'optional': True}),
        ('req-body', KDC_REQ_BODY, {'explicit': 4}),
    ]

class KRB_KDC_REP(Sequence):
    _fields = [
        ('pvno', Integer, {'explicit': 0}),
        ('msg-type', Integer, {'explicit': 1}),
        ('padata', PA_DATA_SEQUENCE_OF, {'explicit': 2, 'optional': True}),
        ('crealm', Realm, {'explicit': 3}),
        ('cname', PrincipalName, {'explicit': 4}),
        ('ticket', Ticket, {'explicit': 5}),
        ('enc-part', EncryptedData, {'explicit': 6}),
    ]

class KRB_AS_REQ(KRB_KDC_REQ):
    explicit = (APPLICATION_TAG, AS_REQ_TAG_NUMBER)

class KRB_AS_REP(KRB_KDC_REP):
    explicit = (APPLICATION_TAG, AS_REP_TAG_NUMBER)

class KRB_ERROR(Sequence):
    explicit = (APPLICATION_TAG, KRB_ERROR_TAG_NUMBER)
    _fields = [
        ('pvno', Integer, {'explicit': 0}),
        ('msg-type', Integer, {'explicit': 1}),
        ('ctime', KerberosTime, {'explicit': 2, 'optional': True}),
        ('cusec', Integer, {'explicit': 3, 'optional': True}),
        ('stime', KerberosTime, {'explicit': 4}),
        ('susec', Integer, {'explicit': 5}),
        ('error-code', Integer, {'explicit': 6}),
        ('crealm', Realm, {'explicit': 7, 'optional': True}),
        ('cname', PrincipalName, {'explicit': 8, 'optional': True}),
        ('realm', Realm, {'explicit': 9}),
        ('sname', PrincipalName, {'explicit': 10}),
        ('e-text', KerberosString, {'explicit': 11, 'optional': True}),
        ('e-data', OctetString, {'explicit': 12, 'optional': True}),
    ]

class ETYPE_INFO2_ENTRY(Sequence):
    _fields = [
        ('etype', Integer, {'explicit': 0}),
        ('salt', KerberosString, {'explicit': 1, 'optional': True}),
        ('s2kparams', OctetString, {'explicit': 2, 'optional': True})
    ]

class ETYPE_INFO2(SequenceOf):
    _child_spec = ETYPE_INFO2_ENTRY


def build_as_req(username: str, domain: str) -> AnyType:
    as_req = KRB_AS_REQ()
    as_req['pvno'] = 5
    as_req['msg-type'] = AS_MSG_TYPE

    req_body = KDC_REQ_BODY()
    req_body['kdc-options'] = KDCOptions(set())
    # TODO: check if some flags are necessary in some cases
    #req_body['kdc-options'] = KDCOptions({'renewable-ok'})

    cname = PrincipalName()
    cname['name-type'] = NT_PRINCIPAL
    cname['name-string'] = KerberosStrings([username])
    req_body['cname'] = cname

    req_body['realm'] = domain

    sname = PrincipalName()
    sname['name-type'] = NT_SRV_INST
    sname['name-string'] = KerberosStrings(['krbtgt', domain])
    req_body['sname'] = sname

    req_body['till'] = KerberosTime(TIME_T_ZERO)

    # TODO: ensure those properties from RFC 4120 :
    # - "Nonces MUST NEVER be reused"
    # - "The encrypted part of the KRB_AS_REP message also contains the nonce
    # that MUST be matched with the nonce from the KRB_AS_REQ message"
    # XXX: it seems that the nonce cannot be bigger than 0x7FFFFFFF. Why ? The
    # RFC says that the nonce is a uint32, its max value should be 0xFFFFFFFF.
    # 0x7FFFFFFF is the max value of an int32.
    #req_body['nonce'] = random.randint(0, UINT32_MAX_VAL)
    req_body['nonce'] = random.randint(0, INT32_MAX_VAL)

    etype = Integers([AES128_CTS_HMAC_SHA1_96_ENC_TYPE, AES256_CTS_HMAC_SHA1h96_ENC_TYPE])
    req_body['etype'] = etype

    as_req['req-body'] = req_body

    return as_req.dump()


def send_as_req(dc: str, username: str, domain: str, udp: bool = False) -> bytes:
    if udp:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect((dc, KERBEROS_PORT))
            s.sendall(build_as_req(username, domain))
            s.settimeout(10)
            return s.recv(1024)
    else:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((dc, KERBEROS_PORT))
            data = build_as_req(username, domain)
            # RFC 4120: "Each request (KRB_KDC_REQ) and response (KRB_KDC_REP
            # or KRB_ERROR) sent over the TCP stream is preceded by the length
            # of the request as 4 octets in network byte order"
            request_length = struct.pack('!i', len(data))
            s.sendall(request_length + data)

            response_length = struct.unpack('!i', s.recv(4))[0]
            return s.recv(response_length)


def get_salt_from_rep(kdc_rep: bytes) -> str:
    tag = Any.load(kdc_rep).tag
    if tag == KRB_ERROR_TAG_NUMBER:
        err = KRB_ERROR.load(kdc_rep)
        error_code = err['error-code'].native
        if error_code == KRBErrorCode.KDC_ERR_PREAUTH_REQUIRED:
            for padata in PA_DATA_SEQUENCE_OF.load(err['e-data'].native):
                if padata['padata-type'].native == PA_ETYPE_INFO2:
                    etype = ETYPE_INFO2()
                    for pa_etype_info2_value in etype.load(padata['padata-value'].native):
                        if (pa_etype_info2_value['etype'].native == AES256_CTS_HMAC_SHA1h96_ENC_TYPE
                            or pa_etype_info2_value['etype'].native == AES128_CTS_HMAC_SHA1_96_ENC_TYPE):
                            # XXX: Adding str just for mypy
                            return str(pa_etype_info2_value['salt'].native)
        else:
            raise Exception(f"Could not retrieve salt from AS_REP, got Kerberos error {KRBErrorCode(error_code).name} ({error_code})")
    elif tag == AS_REP_TAG_NUMBER:
        # In this case the gMSA has the DONT_REQUIRE_PREAUTH flag in its
        # userAccountControl attribute
        as_rep = KRB_AS_REP.load(kdc_rep)
        for padata in as_rep['padata'].native:
            if padata['padata-type'] == PA_ETYPE_INFO2:
                etype = ETYPE_INFO2()
                for pa_etype_info2_value in etype.load(padata['padata-value']):
                    if (pa_etype_info2_value['etype'].native == AES256_CTS_HMAC_SHA1h96_ENC_TYPE
                        or pa_etype_info2_value['etype'].native == AES128_CTS_HMAC_SHA1_96_ENC_TYPE):
                        # XXX: Adding str just for mypy
                        return str(pa_etype_info2_value['salt'])
    raise Exception("Could not retrieve salt from AS_REP (tag number %d)" % tag)


def get_salt_from_preauth(dc: str, username: str, domain: str) -> str:
    return get_salt_from_rep(send_as_req(dc, username, domain))


def get_salt_from_heuristic(sam_account_name: str, domain: str) -> str:
    """
    Generate salt for the gMSA account (considered as a computer)

    See [MS-KILE] 3.1.1.2
    """
    sAMAccountName = sam_account_name.rstrip('$')
    return f'{domain.upper()}host{sAMAccountName}.{domain.lower()}'
