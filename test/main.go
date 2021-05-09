package main

import (
	"flag"
	"fmt"
)

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
	fmt.Printf("%v - %s", *expiry, flag.Args())
}
