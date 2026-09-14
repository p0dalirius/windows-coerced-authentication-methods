# MS-CMRP - Remote call to ApiBackupClusterDatabase (opnum 104)

## Summary

+ **Protocol**: [[MS-CMRP]: Failover Cluster: Management API (ClusAPI) Protocol](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-cmrp/ba4117c0-530e-4e70-a085-4b4cf5bbf193)

+ **Interface**: ClusAPI, UUID `b97db8b2-4c63-11cf-bff6-08002be23f2f`. On the tested host the registered interface version is **3.0** (binding with version 2.0 fails `ept_s_not_registered`).

+ **Transport**: `ncacn_ip_tcp` (dynamic port via the endpoint mapper). Only present when the **Cluster service (ClusSvc) is running** — i.e. a cluster has been formed. Installing the Failover Clustering *feature* alone does not register the endpoint.

+ **Function name**: [`ApiBackupClusterDatabase`](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-cmrp/99990857-f857-402e-8018-b7eaca1fc6c1)

+ **Function operation number**: `104`

+ **Authenticated**: Yes (cluster administrative access)

## Description

`ApiBackupClusterDatabase` was investigated as a coercion candidate: `lpszPathName` is a backup
directory path, and per the specification a UNC path would make the cluster service (machine
account) authenticate outbound to it. The call takes no cluster context handle, so it can be
invoked directly after binding.

```cpp
error_status_t ApiBackupClusterDatabase(
   [in, string] LPCWSTR lpszPathName,
   [out] error_status_t *rpc_status
 );
```

## Testing status — NOT a coercion vector on Windows Server 2025 (method not implemented)

Tested against **Windows Server 2025** (domain controller) with a formed single-node cluster
(`CL01`), 2026-09-14.

- With the cluster running, the ClusAPI interface is registered in the endpoint mapper
  ("Microsoft Cluster Server API") and binds successfully at **interface version 3.0** over
  `ncacn_ip_tcp` (NTLM + packet privacy).
- Calling `ApiBackupClusterDatabase` (opnum 104) with `lpszPathName = \\<listener>\share\clusbak`
  returned **`0x00000078` ERROR_CALL_NOT_IMPLEMENTED**, and the listener recorded **no** outbound
  connection.

The legacy RPC cluster-database backup exposed by this opnum is **not implemented** on current
Windows (cluster database backup is performed through the VSS writer mechanism instead). Because the
server never reaches any path handling, `lpszPathName` is never dereferenced and **no coercion
occurs**. This is a server-implementation behavior and could differ on much older Windows Server
releases where the method may have been implemented.

### Prerequisite note

Even reaching the call requires a **formed cluster** (ClusSvc running). On a host with only the
Failover Clustering feature installed but no cluster created, the ClusAPI endpoint is not registered
(`ept_s_not_registered`) and the interface is unreachable.

## References

+ [MS-CMRP]: Failover Cluster: Management API (ClusAPI) Protocol: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-cmrp/ba4117c0-530e-4e70-a085-4b4cf5bbf193

+ `ApiBackupClusterDatabase` (opnum 104): https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-cmrp/99990857-f857-402e-8018-b7eaca1fc6c1
