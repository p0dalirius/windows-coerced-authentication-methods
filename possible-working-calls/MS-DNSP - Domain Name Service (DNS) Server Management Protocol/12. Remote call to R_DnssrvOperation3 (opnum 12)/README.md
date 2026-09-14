# MS-DNSP - Remote call to R_DnssrvOperation3 (opnum 12)

## Summary

+ **Protocol**: [[MS-DNSP]: Domain Name Service (DNS) Server Management Protocol](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dnsp/f97756c9-3783-428b-9451-b376f877319a)

+ **Protocol UUID**: 50abc2a4-574d-40b3-9d66-ee4fd5fba076

+ **Protocol version**: 0.0

+ **SMB Named pipe**: `\PIPE\DNSSERVER`

+ **Function name**: [`R_DnssrvOperation3`](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dnsp/54044c36-4e9e-44fb-80df-ffb026939b8b)

+ **Function operation number**: `12`

+ **Authenticated**: Yes


## Description

In order to call a remote procedure to trigger an authentication from the remote machine to an arbitrary target, we first need to authenticate to the remote machine, usually on SMB. Then we need to connect to the remote SMB pipe `\PIPE\DNSSERVER` and bind to the desired [`MS-DNSP`](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dnsp/f97756c9-3783-428b-9451-b376f877319a) protocol (with uuid `50abc2a4-574d-40b3-9d66-ee4fd5fba076` and version `0.0`) in order to perform remote procedure calls to functions in the [`MS-DNSP`](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dnsp/f97756c9-3783-428b-9451-b376f877319a) protocol.

This method is a versioned variant of [`R_DnssrvOperation` (opnum 0)](../00.%20Remote%20call%20to%20R_DnssrvOperation%20(opnum%200)/README.md), adding client-version / settings-flag parameters. It dispatches the same `pszOperation` set, so the **`LogFilePath` coercion is expected to work through this call as well**.

`LogFilePath` was confirmed as a working coercion via `R_DnssrvOperation` (opnum 0) on **Windows Server 2025**: setting `pszOperation="LogFilePath"`, `dwTypeId=DNSSRV_TYPEID_LPWSTR`, `pData.WideString = \<listener>\share\x` makes the DNS server (the machine account) authenticate to the listener immediately, no restart. It requires DnsAdmins (write on the DNS Server Configuration ACL). Only opnum 0 was exercised in testing; see that folder's README for the full method and evidence. The `ZoneExport` operation is **not** a vector (the server confines the export filename to a bare name in the DNS directory).

## Function technical detail

```cpp
LONG R_DnssrvOperation3(
   [in]                           handle_t            hBindingHandle,
   [in]                           DWORD               dwClientVersion,
   [in]                           DWORD               dwSettingFlags,
   [in, unique, string]           LPCWSTR             pwszServerName,
   [in, unique, string]           LPCSTR              pszZone,
   [in, unique, string]           LPCWSTR             pwszZoneScopeName,
   [in]                           DWORD               dwContext,
   [in, unique, string]           LPCSTR              pszOperation,
   [in]                           DWORD               dwTypeId,
   [in, switch_is(dwTypeId)]      DNSSRV_RPC_UNION    pData
 );
```

## References

+ Documentation of protocol [MS-DNSP]: Domain Name Service (DNS) Server Management Protocol: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dnsp/f97756c9-3783-428b-9451-b376f877319a

+ Documentation of function `R_DnssrvOperation3`: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dnsp/54044c36-4e9e-44fb-80df-ffb026939b8b