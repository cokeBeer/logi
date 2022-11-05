package main

import (
	"github.com/cokeBeer/logi/internal/runner"
	"github.com/cokeBeer/logi/pkg/payload"
	"github.com/cokeBeer/logi/pkg/wordlist"
	"github.com/projectdiscovery/goflags"
)

var (
	option = &runner.Option{}
)

func main() {
	readConfig()
	logiRunner := runner.New(option)
	logiRunner.Run()
}

func readConfig() *goflags.FlagSet {

	flagSet := goflags.NewFlagSet()
	flagSet.SetDescription(`Logi is a LDAP/MySQL server focusing on pingback deserialize recon and exploit.`)

	flagSet.CreateGroup("basic", "basic config",
		flagSet.IntVarP(&option.Mode, "mode", "m", 0, "1 for poc , 2 for probe, 3 for exploit"),
		flagSet.IntVarP(&option.Type, "type", "t", 0, "1 for ldap, 2 for mysql"),
	)

	flagSet.CreateGroup("serve", "serve config",
		flagSet.StringVarP(&option.IP, "ip", "i", "0.0.0.0", "ip for binding"),
		flagSet.StringVarP(&option.Port, "port", "p", "1389", "port for binding"),
	)

	flagSet.CreateGroup("probe", "probe config",
		flagSet.StringVarP(&option.Domain, "domain", "d", "", "domain for dns lookup"),
		flagSet.StringVarP(&option.DictName, "dictname", "w", "yso", "wordlist name for probe, support: "+wordlist.Manager.String()),
		flagSet.StringVarP(&option.DictPath, "dictpath", "wp", "", "wordlist path for probe"),
	)

	flagSet.CreateGroup("exploit", "exploit config",
		flagSet.StringVarP(&option.Gadget, "gadget", "g", "", "gadget for exploit, support: "+payload.IExecManager.String()),
		flagSet.StringVarP(&option.Command, "command", "c", "", "command for exploit"),
		flagSet.StringVarP(&option.Shell, "shell", "s", "", "reverse shell, e.g. 127.0.0.1:7777"),
		flagSet.StringVarP(&option.Binary, "binary", "b", "", "payload path for exploit"),
	)

	flagSet.Parse()

	return flagSet
}
