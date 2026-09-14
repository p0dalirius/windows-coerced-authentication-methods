# MS-DNSP - Remote call to R_DnssrvComplexOperation (opnum 2)

## Summary

+ **Protocol**: [[MS-DNSP]: Domain Name Service (DNS) Server Management Protocol](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dnsp/f97756c9-3783-428b-9451-b376f877319a)

+ **Protocol UUID**: 50abc2a4-574d-40b3-9d66-ee4fd5fba076

+ **Interface version**: 5.0

+ **Transport**: `ncacn_ip_tcp` (dynamic port resolved through the endpoint mapper on TCP/135). On the tested Windows Server 2025 DC the `\PIPE\DNSSERVER` named pipe was **not** present.

+ **Function name**: [`R_DnssrvComplexOperation`](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dnsp/864a6971-f664-47b9-b012-826fd2b0a409)

+ **Function operation number**: `2`

+ **Authenticated**: Yes

## Description

`R_DnssrvComplexOperation` is a generic dispatcher that both takes input (`pDataIn`) and returns
output (`ppDataOut`); the action is selected by `pszOperation`. It is used for enumerations and for
operations that produce data, including **`ExportSettings`**, which was investigated here as a
potential coercion surface (it needs only Read privilege). It is **not** a coercion vector — see
below.

## `ExportSettings` — NOT a coercion vector

`ExportSettings` is one of the few operations that require only **Read** privilege on the DNS Server
Configuration ACL (the R_Dnssrv* read-privilege exception list in [MS-DNSP] 3.1.6.1), which made it
attractive as a low-privilege primitive. However, it writes to a **fixed output path** — a text file
named `DnsSettings.txt` in the DNS directory (`%systemroot%\system32\dns`). The client does not
supply the output path, so there is nothing to point at a remote listener and no coercion is
possible.

In testing against **Windows Server 2025** (DC, DNS role, over `ncacn_ip_tcp`), invoking
`ExportSettings` through `R_DnssrvComplexOperation` returned `ERROR_INVALID_PARAMETER` for the
input forms tried (both a NULL input and an `LPSTR` input), consistent with the operation taking no
client-controlled path argument. The fixed-path behavior documented in the specification is what
rules it out regardless of the exact input form.

## Function technical detail

```cpp
LONG R_DnssrvComplexOperation(
   [in]                                   handle_t                  hBindingHandle,
   [in, unique, string]                   LPCWSTR                   pwszServerName,
   [in, unique, string]                   LPCSTR                    pszZone,
   [in, unique, string]                   LPCSTR                    pszOperation,
   [in]                                   DWORD                     dwTypeIn,
   [in, switch_is(dwTypeIn)]              DNSSRV_RPC_UNION          pDataIn,
   [out]                                  PDWORD                    pdwTypeOut,
   [out, switch_is(*pdwTypeOut)]          DNSSRV_RPC_UNION*         ppDataOut
 );
```

## Notes on the operation variants

The same operations are exposed by `R_DnssrvComplexOperation2` (opnum 7) and
`R_DnssrvComplexOperation3` (opnum 14), which add version/settings-flag parameters. The
`ExportSettings` conclusion (fixed output path, no coercion) applies to those as well.

## References

+ Documentation of protocol [MS-DNSP]: Domain Name Service (DNS) Server Management Protocol: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dnsp/f97756c9-3783-428b-9451-b376f877319a

+ Documentation of function `R_DnssrvComplexOperation` (opnum 2): https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dnsp/864a6971-f664-47b9-b012-826fd2b0a409
