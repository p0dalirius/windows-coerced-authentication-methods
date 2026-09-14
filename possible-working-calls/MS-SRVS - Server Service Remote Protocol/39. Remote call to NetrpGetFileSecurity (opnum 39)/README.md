# MS-SRVS - Remote call to NetrpGetFileSecurity (opnum 39)

## Summary

+ **Protocol**: [[MS-SRVS]: Server Service Remote Protocol](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-srvs/accf23b0-0f57-441c-9185-43041f1b0ee9)

+ **Protocol UUID**: 4b324fc8-1670-01d3-1278-5a47bf6ee188

+ **Protocol version**: 3.0

+ **SMB Named pipe**: `\PIPE\srvsvc`

+ **Function name**: [`NetrpGetFileSecurity`](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-srvs/753f7ac0-3bf3-4f9f-a479-2834aac7096e)

+ **Function operation number**: `39`

+ **Authenticated**: Yes (any authenticated user; `\PIPE\srvsvc` is present on every Windows host)

## Description

`NetrpGetFileSecurity` returns the security descriptor protecting a file or directory. The
caller supplies a `ShareName` (which must already exist on the target) and an `lpFileName`
that is "the full path to the file from the *ShareName* parameter". The server then, per
[MS-SRVS] 3.1.4.29:

> The *ShareName* parameter specifies a local share name on the server. The server MUST
> locate a **Share** from **ShareList**, where *ShareName* matches **Share.ShareName**. If
> no share is found, the server MUST fail the call with NERR_NetNameNotFound. The server
> MUST then combine **Share.LocalPath** with the *lpFileName* parameter in order to create
> a fully qualified path name that is local to the server. [...] The server MUST then obtain
> the security descriptor [...] for the local file that the path name obtains specifies [...]

Because the server *opens* the resolved path to read its security descriptor, this call was
a candidate coercion primitive: the specification mandates no validation of `lpFileName`, so
if the combination `Share.LocalPath + lpFileName` could be steered to a UNC path
(`\\<listener>\share\file`), the server would authenticate outbound to the listener with its
machine account. It requires only an authenticated user, and `SYSVOL` / `NETLOGON` provide
ready-made shares on a domain controller.

## Function technical detail

```cpp
DWORD NetrpGetFileSecurity(
   [in, string, unique] SRVSVC_HANDLE ServerName,
   [in, string, unique] WCHAR* ShareName,
   [in, string] WCHAR* lpFileName,
   [in] SECURITY_INFORMATION RequestedInformation,
   [out] PADT_SECURITY_DESCRIPTOR* SecurityDescriptor
 );
```

+ **ServerName**: `SRVSVC_HANDLE`; the server MUST ignore it.
+ **ShareName**: null-terminated UTF-16 share name. MUST match an existing `Share.ShareName`, otherwise the call fails with `NERR_NetNameNotFound`.
+ **lpFileName**: null-terminated UTF-16 path, "the full path to the file from the *ShareName* parameter". Combined with `Share.LocalPath` by the server.
+ **RequestedInformation**: `SECURITY_INFORMATION` bitmask ([MS-DTYP] 2.4.7), e.g. `OWNER_SECURITY_INFORMATION` (0x1).
+ **SecurityDescriptor**: `[out]` self-relative security descriptor of the resolved file.

## Testing status — NOT a coercion vector on the tested build

Tested against **Windows Server 2025 (build 26100.32995)**, domain controller, `\PIPE\srvsvc`,
as an authenticated user, with an SMB listener on the target UNC path.

The call itself works: with a legitimate `lpFileName` (a real path under the share) it returns
`NERR_Success` and a valid security descriptor. However, **no `lpFileName` payload could be
made to resolve to a remote UNC path, and the listener recorded zero outbound connections
across the full battery of attempts.** The implementation on this build does not exhibit the
naive concatenation the specification's wording allows; instead it **canonicalizes
`lpFileName` and confines the result to the share's `LocalPath` subtree.**

### Shares and their `Share.LocalPath` on the test DC

| Share | LocalPath |
|---|---|
| `SYSVOL` | `C:\WINDOWS\SYSVOL\sysvol` |
| `NETLOGON` | `C:\WINDOWS\SYSVOL\sysvol\<domain>\SCRIPTS` |
| `C$` | `C:\` |
| `ADMIN$` | `C:\WINDOWS` |
| `IPC$` | *(empty)* |

### What was attempted (all against `SYSVOL` unless noted) and observed

| `lpFileName` payload | Result |
|---|---|
| `\\<listener>\share\x` (UNC as lpFileName) | `0x3` ERROR_PATH_NOT_FOUND — combined under `C:\...`, stays local |
| `\..\..\..\..\..\..\..\..\..\..\<listener>\share\x` | `0x3` — traversal clamped to share root, stays local |
| `\\\\<listener>\share\x` (extra slashes) | `0x3` |
| `\??\UNC\<listener>\share\x`, `Global??\UNC\...` | `0x7b` ERROR_INVALID_NAME |
| `\GLOBALROOT\Device\Mup\<listener>\share\x` | `0x3` |
| `\\?\UNC\<listener>\share\x` | `0x7b` |
| forward-slash variants `/../../..//<listener>/share/x` | `0x3` |
| same UNC payloads via `C$` / `ADMIN$` | `0x3` |
| any UNC payload via `IPC$` | `0x41` ERROR_NETWORK_ACCESS_DENIED — server refuses `IPC$` (not a disk share) |

### Why it is confined — path handling proven by calibration

The server canonicalizes `lpFileName` (collapsing `..`) and clamps any traversal at the
share root. This was established with paths whose outcome distinguishes the models:

| `lpFileName` | Result | Interpretation |
|---|---|---|
| `\TMP-W-2025.local` (real subdir of share root) | SUCCESS | direct child resolves |
| `\..\TMP-W-2025.local` | SUCCESS | `..` above root is clamped to the root, not honored upward |
| `\..\..\..\..\..\TMP-W-2025.local` | SUCCESS | any number of leading `..` clamps to the root |
| `\foo\..\TMP-W-2025.local` | SUCCESS | in-path `..` collapses normally (`foo\..` cancels) |
| `\..\..\..\Windows` | `0x2` ERROR_FILE_NOT_FOUND | resolves to `<shareRoot>\Windows`, i.e. clamped to root, not `C:\Windows` |
| `\..\..\..\Windows\System32` | `0x3` ERROR_PATH_NOT_FOUND | same, intermediate dir absent under the share root |

The combination of "in-path `..` collapses" *and* "leading `..` clamps to the share root"
is only consistent with proper path canonicalization confined to `Share.LocalPath`. Since
every real disk share has a drive-rooted `LocalPath` (`C:\...`), and a canonicalized path
confined under `C:\...` can never begin with `\\`, there is no way to express a UNC target
through `lpFileName`. `ShareName` cannot carry a UNC either, as it must match an existing
local share.

### Conclusion

On Windows Server 2025 (26100.32995), `NetrpGetFileSecurity` is **not** a coercion primitive:
the server canonicalizes and root-confines the `Share.LocalPath + lpFileName` path, so no
authenticated caller can drive it to a remote UNC. The specification does not mandate this
validation, so the behavior is implementation-provided and could differ on older or
non-Windows SMB server implementations. The one residual theoretical vector — a share whose
`Share.LocalPath` is itself a UNC — is out of scope for a low-privilege primitive, since
creating such a share requires administrative rights and standard shares (`SYSVOL`,
`NETLOGON`, `C$`, `ADMIN$`) are all drive-rooted.

## References

+ Documentation of protocol [MS-SRVS]: Server Service Remote Protocol: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-srvs/accf23b0-0f57-441c-9185-43041f1b0ee9

+ Documentation of function `NetrpGetFileSecurity` (opnum 39): https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-srvs/753f7ac0-3bf3-4f9f-a479-2834aac7096e
