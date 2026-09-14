# MS-DNSP - Remote call to R_DnssrvComplexOperation2 (opnum 7)

## Summary

+ **Protocol**: [[MS-DNSP]: Domain Name Service (DNS) Server Management Protocol](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dnsp/f97756c9-3783-428b-9451-b376f877319a)

+ **Protocol UUID**: 50abc2a4-574d-40b3-9d66-ee4fd5fba076

+ **Protocol version**: 0.0

+ **SMB Named pipe**: `\PIPE\DNSSERVER`

+ **Function name**: [`R_DnssrvComplexOperation2`](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dnsp/d28e3ba8-5742-417d-ad6d-2e0139ab2ad9)

+ **Function operation number**: `7`

+ **Authenticated**: Yes


## Description

In order to call a remote procedure to trigger an authentication from the remote machine to an arbitrary target, we first need to authenticate to the remote machine, usually on SMB. Then we need to connect to the remote SMB pipe `\PIPE\DNSSERVER` and bind to the desired [`MS-DNSP`](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dnsp/f97756c9-3783-428b-9451-b376f877319a) protocol (with uuid `50abc2a4-574d-40b3-9d66-ee4fd5fba076` and version `0.0`) in order to perform remote procedure calls to functions in the [`MS-DNSP`](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dnsp/f97756c9-3783-428b-9451-b376f877319a) protocol.

This method is a versioned variant of [`R_DnssrvComplexOperation` (opnum 2)](../02.%20Remote%20call%20to%20R_DnssrvComplexOperation%20(opnum%202)/README.md), adding client-version / settings-flag parameters. It dispatches the same `pszOperation` set.

The `ExportSettings` operation reachable through this family is **not** a coercion vector: it writes to a fixed output path (`DnsSettings.txt` in `%systemroot%\system32\dns`) and takes no client-controlled path, so it cannot be pointed at a listener. See the opnum 2 folder's README for details and test results.

## Function technical detail

```cpp
LONG R_DnssrvComplexOperation2(
   [in]                                 handle_t               hBindingHandle,
   [in]                                 DWORD                  dwClientVersion,
   [in]                                 DWORD                  dwSettingFlags,
   [in, unique, string]                 LPCWSTR                pwszServerName,
   [in, unique, string]                 LPCSTR                 pszZone,
   [in, unique, string]                 LPCSTR                 pszOperation,
   [in]                                 DWORD                  dwTypeIn,
   [in, switch_is(dwTypeIn)]            DNSSRV_RPC_UNION       pDataIn,
   [out]                                PDWORD                 pdwTypeOut,
   [out, switch_is(*pdwTypeOut)]        DNSSRV_RPC_UNION*      ppDataOut
 );
```

## References

+ Documentation of protocol [MS-DNSP]: Domain Name Service (DNS) Server Management Protocol: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dnsp/f97756c9-3783-428b-9451-b376f877319a

+ Documentation of function `R_DnssrvComplexOperation2`: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dnsp/d28e3ba8-5742-417d-ad6d-2e0139ab2ad9