package main

var helpHeader = `
Usage: ./canarytail command [SUBCOMMAND] [OPTIONS]

Commands:
  help		                  Display this help message or help on a command

  init		                  Initialize config and keys to $CANARY_HOME
`
var helpKey = `
  key

      This command is for manipulating cryptographic keys.

      new DOMAIN              Generates a new key for signing canaries and saves
                              to $CANARY_HOME/DOMAIN
`
var helpCanaryHeader = `
  canary

      This command is for manipulating canaries.

`
var helpCanaryNew = `
      new DOMAIN [--OPTIONS]
                              Generates a new canary, signs it using the key located
                              in $CANARY_HOME/DOMAIN, and saves to that same path.

                              Codes provided in OPTIONS will be removed from the canary,
                              signifying that event has triggered the canary.

`
var helpCanaryUpdate = `
      update DOMAIN [--OPTIONS]
                              Updates the existing canary named DOMAIN. If no OPTIONS
                              are provided, it merely updates the signature date. If
                              no EXPIRY is provided, it reuses the previous value
                              (e.g. renewing for a month).

                              Codes provided in OPTIONS will be removed from the canary,
                              signifying that event has triggered the canary.
                              

`
var helpCanaryOptions = `
      Valid OPTIONS:

      --expiry:#              Expires in # minutes from now (default: 43200, one month)
      --cease                 Court order to cease operations
      --duress                Under duress (coercion, blackmail, etc)
      --gag                   Gag order received
      --raid                  Raided, but data unlikely compromised
      --seize                 Hardware or data seized, unlikely compromised
      --subp                  Subpoena received
      --trap                  Trap and trace order received
      --war                   Warrant received
      --xcred                 Compromised credentials
      --xopers                Operations compromised

`
var helpCanaryValidate = `
      validate [URI]              Validates a canary's signature

`
var helpFooter = `
  version	                  Show version and exit

Environment:
  CANARY_HOME	Location of canarytail config and files (default: $PWD)
`
