package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"time"

	"github.com/alecthomas/kong"
	canarytail "github.com/canarytail/client"
)

const version = "0.2"

func main() {
	expiry := flag.Int("expiry", 0, "xpires in # minutes from now (default: 43200, one month)")
	cease := flag.Bool("cease", false, "Court order to cease operations")
	duress := flag.Bool("duress", false, "Under duress (coercion, blackmail, etc)")
	gag := flag.Bool("gag", false, "Gag order received")
	raid := flag.Bool("raid", false, "Raided, but data unlikely compromised")
	seize := flag.Bool("seize", false, "Hardware or data seized, unlikely compromised")
	subp := flag.Bool("subp", false, "Subpoena received")
	trap := flag.Bool("trap", false, "Trap and trace order received")
	war := flag.Bool("war", false, "Warrant received")
	xcred := flag.Bool("xcred", false, "Compromised credentials")
	xopers := flag.Bool("xopers", false, "Operations compromised")
	flag.Parse()

	if !flag.Parsed() || len(flag.Args()) == 0 || flag.Arg(0) == "help" {
		printUsage()
		return
	}
	switch flag.Arg(0) {
	case "help":
		printHelp(flag.Args())
	case "version":
		printVersion()
	case "init":
		initCmd()
	case "key":
		keyCmd(flag.Args())
	case "canary":
		canaryCmd(canaryOptions{
			Expiry: *expiry,
			GAG:    *gag,
			TRAP:   *trap,
			DURESS: *duress,
			XCRED:  *xcred,
			XOPERS: *xopers,
			WAR:    *war,
			SUBP:   *subp,
			CEASE:  *cease,
			RAID:   *raid,
			SEIZE:  *seize,
		}, flag.Args())
	}
}

func printUsage() {
	fmt.Print(helpHeader)
	fmt.Print(helpKey)
	fmt.Print(helpCanaryHeader)
	fmt.Print(helpCanaryNew)
	fmt.Print(helpCanaryUpdate)
	fmt.Print(helpCanaryOptions)
	fmt.Print(helpCanaryValidate)
	fmt.Print(helpFooter)
}

func printHelp(args []string) {
	if len(args) > 1 {
		switch args[1] {
		case "key":
			fmt.Print(helpKey)
		case "canary":
			fmt.Print(helpCanaryHeader)
			if len(args) > 2 {
				switch args[2] {
				case "new":
					fmt.Print(helpCanaryNew)
					fmt.Print(helpCanaryOptions)
				case "update":
					fmt.Print(helpCanaryUpdate)
					fmt.Print(helpCanaryOptions)
				case "validate":
					fmt.Print(helpCanaryValidate)
					fmt.Print(helpCanaryOptions)
				}
			} else {
				fmt.Print(helpCanaryNew)
				fmt.Print(helpCanaryUpdate)
				fmt.Print(helpCanaryValidate)
				fmt.Print(helpCanaryOptions)
			}
		}
	} else {
		printUsage()
	}
}

func initCmd() {
	dir := canaryHomeDir()
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		os.Mkdir(dir, 0700)
	}
}

func keyCmd(args []string) {
	if len(args) == 2 {
		keyNew()
	} else {
		fmt.Print(helpKey)
	}
}

func keyNew(args []string) {
	stagingPath := canaryDirSafe(cmd.Domain)

	fmt.Printf("Generating signing key pair for %v at %v...\n", cmd.Domain, stagingPath)
	defer fmt.Println("Done.")

	publicKey, privateKey, err := canarytail.GenerateKeyPair()
	if err != nil {
		panic(fmt.Errorf("Could not generate key pair: %v", err))
	}

	err = writeToFile(path.Join(stagingPath, "public.b64"), base64.StdEncoding.EncodeToString(publicKey))
	if err != nil {
		return err
	}

	err = writeToFile(path.Join(stagingPath, "private.b64"), base64.StdEncoding.EncodeToString(privateKey))
	if err != nil {
		return err
	}

	fmt.Printf("Generating panic key pair for %v at %v...\n", cmd.Domain, stagingPath)

	publicPanicKey, privatePanicKey, err := canarytail.GenerateKeyPair()
	if err != nil {
		panic(fmt.Errorf("Could not generate panic key pair: %v", err))
	}

	err = writeToFile(path.Join(stagingPath, "panic-public.b64"), base64.StdEncoding.EncodeToString(publicPanicKey))
	if err != nil {
		return err
	}

	err = writeToFile(path.Join(stagingPath, "panic-private.b64"), base64.StdEncoding.EncodeToString(privatePanicKey))
	if err != nil {
		return err
	}

}

type canaryOptions struct {
	Expiry int
	GAG    bool
	TRAP   bool
	DURESS bool
	XCRED  bool
	XOPERS bool
	WAR    bool
	SUBP   bool
	CEASE  bool
	RAID   bool
	SEIZE  bool
}

func getCodes(cmd canaryOptions) []string {
	codes := make([]string, 0)
	if cmd.GAG {
		codes = append(codes, "gag")
	}
	if cmd.TRAP {
		codes = append(codes, "trap")
	}
	if cmd.DURESS {
		codes = append(codes, "duress")
	}
	if cmd.XCRED {
		codes = append(codes, "xcred")
	}
	if cmd.XOPERS {
		codes = append(codes, "xopers")
	}
	if cmd.WAR {
		codes = append(codes, "war")
	}
	if cmd.SUBP {
		codes = append(codes, "subp")
	}
	if cmd.CEASE {
		codes = append(codes, "cease")
	}
	if cmd.RAID {
		codes = append(codes, "raid")
	}
	if cmd.SEIZE {
		codes = append(codes, "seize")
	}
	return canarytail.InverseCodes(codes)
}

type keyPairReader func(dir string) (ed25519.PublicKey, ed25519.PrivateKey, error)

func canaryCmd(options canaryOptions, args []string) {
	if len(args) < 3 {
		printCanaryHelp()
		return
	}
	domain := args[2]
	switch args[1] {
	case "new":
		generateCanary(options, readKeyPair, domain)
	case "update":
		updateCanary(options, readKeyPair, domain)
	}
}

func generateCanary(cmd canaryOptions, signingKeyPairReader keyPairReader, dir string) {
	// read the key pair for this canary alias
	publickKey, _, err := readKeyPair(dir)
	if err != nil {
		fmt.Printf("Problem with the public key: %s", err)
		return
	}

	// read the panic key pair for this canary alias
	publicPanicKey, _, err := readPanicKeyPair(dir)
	if err != nil {
		fmt.Printf("Problem with the panic key: %s", err)
		return
	}

	// read the key pair for this canary alias
	publicSigningKey, privateSigningKey, err := signingKeyPairReader(dir)
	if err != nil {
		fmt.Printf("Problem trying reading key pair: %s", err)
		return
	}

	// compose the canary
	canary := &canarytail.Canary{Claim: canarytail.CanaryClaim{
		Domain:     dir,
		Codes:      getCodes(cmd),
		Release:    time.Now().Format(canarytail.TimestampLayout),
		Freshness:  canarytail.GetLastBlockChainBlockHashFormatted(),
		Expiry:     time.Now().Add(time.Duration(cmd.Expiry) * time.Minute).Format(canarytail.TimestampLayout),
		Version:    canarytail.StandardVersion,
		PublicKeys: []string{canarytail.FormatKey(publickKey)},
		PanicKey:   canarytail.FormatKey(publicPanicKey),
	}}

	// sign it
	err = canary.Sign(privateSigningKey, publicSigningKey)
	if err != nil {
		fmt.Printf("Problem trying sign domain: %s", err)
		return
	}

	// and print it
	canaryFormatted := canary.Format()
	writeToFile(path.Join(dir, "canary.json"), canaryFormatted)
	fmt.Println(canaryFormatted)
	return
}

func updateCanary(cmd canaryOptions, signingKeyPairReader keyPairReader, dir string) {
	canary, err := readCanaryFile(path.Join(dir, "canary.json"))
	if err != nil {
		fmt.Printf("Problem with the public key: %s", err)
		return
	}

	// read the panic key pair for this canary alias
	publicPanicKey, _, err := readPanicKeyPair(dir)
	if err != nil {
		fmt.Printf("Problem with the panic key: %s", err)
		return
	}

	// read the key pair for this canary alias
	publicSigningKey, privateSigningKey, err := signingKeyPairReader(dir)
	if err != nil {
		fmt.Printf("Problem trying reading key pair: %s", err)
		return
	}

	// update the canary
	canary.Claim.Release = time.Now().Format(canarytail.TimestampLayout)
	canary.Claim.Freshness = canarytail.GetLastBlockChainBlockHashFormatted()
	canary.Claim.Expiry = time.Now().Add(time.Duration(cmd.Expiry) * time.Minute).Format(canarytail.TimestampLayout)
	canary.Claim.Version = canarytail.StandardVersion
	canary.Claim.Codes = getCodes(cmd)

	// if the public key is not there, add it
	publicKeyEnc := canarytail.FormatKey(publicSigningKey)
	if publicKeyEnc != canary.Claim.PanicKey {
		foundPubKey := false
		for _, x := range canary.Claim.PublicKeys {
			if x == publicKeyEnc {
				foundPubKey = true
				break
			}
		}
		if !foundPubKey {
			canary.Claim.PublicKeys = append(canary.Claim.PublicKeys, publicKeyEnc)
		}
	}

	// if the panic key is not the same, error out
	panicKeyEnc := canarytail.FormatKey(publicPanicKey)
	if panicKeyEnc == publicKeyEnc && panicKeyEnc != canary.Claim.PanicKey {
		fmt.Printf("The panic key does not match")
		return
	}

	// sign it
	err = canary.Sign(privateSigningKey, publicSigningKey)
	if err != nil {
		fmt.Printf("Problem trying sign domain: %s", err)
		return
	}

	// and print it
	canaryFormatted := canary.Format()
	writeToFile(path.Join(dir, "canary.json"), canaryFormatted)
	fmt.Println(canaryFormatted)
	return
}

func canaryNewCmd() {
	// make sure the canary doesnt exist yet?
	// initialize the keys if they dont exist yet?
	generateCanary(cmd.canaryOpCmd, readKeyPair)
}

func canaryUpdateCmd() {
	// make sure the canary already exists?
	updateCanary(cmd.canaryOpCmd, readKeyPair)
}

func canaryPanicCmd() {
	// make sure the canary doesnt exist yet?
	// initialize the keys if they dont exist yet?
	updateCanary(cmd.canaryOpCmd, readPanicKeyPair)
}

func canaryValidateCmd() {
	// make sure the canary already exists?
	canary, err := canarytail.Read(cmd.URI)
	if err != nil {
		return err
	}

	fmt.Printf("Validating canary %v...\n", cmd.URI)

	if ok, err := canary.Validate(); !ok {
		return err
	}
	fmt.Println("OK!")
}

func printVersion() {
	fmt.Printf("CLI Version %v\nStandard Version %v\n", version, canarytail.StandardVersion)
}

// helpers

func canaryHomeDir() string {
	dir := os.Getenv("CANARY_HOME")
	if len(dir) == 0 {
		// get home folder
		home, err := os.UserHomeDir()
		if err != nil {
			panic(err)
		}

		return path.Join(home, ".canarytail")
	}
	return dir
}

func canaryDir(alias string) string {
	return path.Join(canaryHomeDir(), alias)
}

// returns the canary dir. if it doesnt exist, it gets created
func canaryDirSafe(alias string) string {
	homeDir := canaryHomeDir()
	if _, err := os.Stat(homeDir); os.IsNotExist(err) {
		os.Mkdir(homeDir, 0700)
	}
	dir := canaryDir(alias)
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		os.Mkdir(dir, 0700)
	}
	return dir
}

func writeToFile(path, contents string) error {
	return ioutil.WriteFile(path, []byte(contents), 0600)
}

func readKeyPair(stagingPath string) (ed25519.PublicKey, ed25519.PrivateKey, error) {
	publicKeyBytes, err := ioutil.ReadFile(path.Join(stagingPath, "public.b64"))
	if err != nil {
		return nil, nil, err
	}

	privateKeyBytes, err := ioutil.ReadFile(path.Join(stagingPath, "private.b64"))
	if err != nil {
		return nil, nil, err
	}

	publicKey, err := base64.StdEncoding.DecodeString(string(publicKeyBytes))
	if err != nil {
		return nil, nil, err
	}

	privateKey, err := base64.StdEncoding.DecodeString(string(privateKeyBytes))
	if err != nil {
		return nil, nil, err
	}

	return publicKey, privateKey, nil
}

func readPanicKeyPair(stagingPath string) (ed25519.PublicKey, ed25519.PrivateKey, error) {
	publicKeyBytes, err := ioutil.ReadFile(path.Join(stagingPath, "panic-public.b64"))
	if err != nil {
		return nil, nil, err
	}

	privateKeyBytes, err := ioutil.ReadFile(path.Join(stagingPath, "panic-private.b64"))
	if err != nil {
		return nil, nil, err
	}

	publicKey, err := base64.StdEncoding.DecodeString(string(publicKeyBytes))
	if err != nil {
		return nil, nil, err
	}

	privateKey, err := base64.StdEncoding.DecodeString(string(privateKeyBytes))
	if err != nil {
		return nil, nil, err
	}

	return publicKey, privateKey, nil
}

func readCanaryFile(path string) (canarytail.Canary, error) {
	canaryJSON, err := ioutil.ReadFile(path)
	if err != nil {
		return canarytail.Canary{}, err
	}

	var canary canarytail.Canary
	err = json.Unmarshal(canaryJSON, &canary)
	return canary, err
}
