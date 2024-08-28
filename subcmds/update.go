package subcmds

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/logging"
	"github.com/future-architect/vuls/models"
	"github.com/future-architect/vuls/reporter"
	"github.com/future-architect/vuls/scanner"
	"github.com/google/subcommands"
	"github.com/k0kubun/pp"
)

// UpdateCmd is subcommand to update vulnerable packages
type UpdateCmd struct {
	configPath       string
	timeoutSec       int
	updateTimeoutSec int
}

// Name return subcommand name
func (*UpdateCmd) Name() string { return "update" }

// Synopsis return synopsis
func (*UpdateCmd) Synopsis() string {
	return `Update vulnerable packages.`
}

// Usage return usage
func (*UpdateCmd) Usage() string {
	return `update:
	update
		[--config=/path/to/config.toml]
		[-results-dir=/path/to/results]
		[--log-to-file]
		[--log-dir=/path/to/log]
		[-timeout=300]
		[-timeout-update=7200]
		[--debug]
		[--quiet]
	`
}

// SetFlags set flag
func (p *UpdateCmd) SetFlags(f *flag.FlagSet) {
	f.BoolVar(&config.Conf.Debug, "debug", false, "Debug mode")
	f.BoolVar(&config.Conf.Quiet, "quiet", false, "Quiet mode. No output on stdout")

	wd, _ := os.Getwd()
	defaultConfPath := filepath.Join(wd, "config.toml")
	f.StringVar(&p.configPath, "config", defaultConfPath, "/path/to/toml")

	defaultLogDir := logging.GetDefaultLogDir()
	f.StringVar(&config.Conf.LogDir, "log-dir", defaultLogDir, "/path/to/log")
	f.BoolVar(&config.Conf.LogToFile, "log-to-file", false, "Output log to file")

	defaultResultsDir := filepath.Join(wd, "results")
	f.StringVar(&config.Conf.ResultsDir, "results-dir", defaultResultsDir, "/path/to/results")

	f.IntVar(&p.timeoutSec, "timeout", 5*60,
		"Number of seconds for processing other than update",
	)

	f.IntVar(&p.updateTimeoutSec, "timeout-update", 120*60,
		"Number of seconds for updating vulnerable packages on all servers",
	)
}

// Execute execute
func (p *UpdateCmd) Execute(_ context.Context, f *flag.FlagSet, _ ...interface{}) subcommands.ExitStatus {
	logging.Log = logging.NewCustomLogger(config.Conf.Debug, config.Conf.Quiet, config.Conf.LogToFile, config.Conf.LogDir, "", "")
	logging.Log.Infof("vuls-%s-%s", config.Version, config.Revision)

	if err := config.Load(p.configPath); err != nil {
		msg := []string{
			fmt.Sprintf("Error loading %s", p.configPath),
			"If you update Vuls and get this error, there may be incompatible changes in config.toml",
			"Please check config.toml template : https://vuls.io/docs/en/config.toml.html",
		}
		logging.Log.Errorf("%s\n%+v", strings.Join(msg, "\n"), err)
		return subcommands.ExitUsageError
	}

	logging.Log.Infof("config: %s", p.configPath)

	dir, err := reporter.JSONDir(config.Conf.ResultsDir, []string{})

	if err != nil {
		logging.Log.Errorf("Failed to read from JSON. err: %+v", err)
		return subcommands.ExitFailure
	}

	logging.Log.Info("Validating config...")
	if !config.Conf.ValidateOnReport() {
		return subcommands.ExitUsageError
	}

	var res models.ScanResults
	if res, err = reporter.LoadScanResults(dir); err != nil {
		logging.Log.Error(err)
		return subcommands.ExitFailure
	}
	logging.Log.Infof("Loaded: %s", dir)

	var servernames []string
	vulnPkgs := make(map[string][]string)

	for _, rs := range res {
		servernames = append(servernames, rs.ServerName)
		var affectedPackages []string
		for _, vulnInfo := range rs.ScannedCves {
			for _, pkg := range vulnInfo.AffectedPackages {
				affectedPackages = append(affectedPackages, pkg.Name)
			}
		}
		vulnPkgs[rs.ServerName] = affectedPackages
	}

	targets := make(map[string]config.ServerInfo)
	for _, arg := range servernames {
		found := false
		for _, info := range config.Conf.Servers {
			if info.BaseName == arg {
				info.Optional["vulnPkgs"] = vulnPkgs[info.BaseName]
				targets[info.ServerName] = info
				found = true
			}
		}
		if !found {
			logging.Log.Errorf("%s is not in config", arg)
			return subcommands.ExitUsageError
		}
	}
	if 0 < len(servernames) {
		// if scan target servers are specified by args, set to the config
		config.Conf.Servers = targets
	} else {
		logging.Log.Info("No server to update...")
		return subcommands.ExitSuccess
	}
	logging.Log.Debugf("%s", pp.Sprintf("%v", targets))

	logging.Log.Info("Validating config...")
	if !config.Conf.ValidateOnScan() {
		return subcommands.ExitUsageError
	}

	s := scanner.Scanner{
		ResultsDir:     config.Conf.ResultsDir,
		TimeoutSec:     p.timeoutSec,
		ScanTimeoutSec: p.updateTimeoutSec,
		Targets:        targets,
		Debug:          config.Conf.Debug,
		Quiet:          config.Conf.Quiet,
		LogToFile:      config.Conf.LogToFile,
		LogDir:         config.Conf.LogDir,
	}

	logging.Log.Info("This command will update vulnerable packages on the targets.")
	logging.Log.Info("Do you want to proceed? [y/N]: ")

	reader := bufio.NewReader(os.Stdin)
	userInput, _ := reader.ReadString('\n')
	confirmation := strings.ToLower(strings.TrimSpace(userInput))

	if confirmation != "y" && confirmation != "yes" {
		logging.Log.Info("Operation aborted.")
		return subcommands.ExitSuccess
	}

	logging.Log.Info("Start updating")

	if err := s.UpdatePackages(); err != nil {
		logging.Log.Errorf("Failed to update: %+v", err)
		return subcommands.ExitFailure
	}

	fmt.Printf("\n\n\n")
	fmt.Println("Operation completed.")

	return subcommands.ExitSuccess
}
