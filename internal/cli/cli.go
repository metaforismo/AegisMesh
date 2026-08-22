// Package cli implements the aegismesh command-line interface: a small
// dispatcher over stdlib flag with structured errors and JSON output modes.
package cli

import (
	"context"
	"fmt"
	"io"
	"strings"
)

// Command is one subcommand of the binary.
type Command interface {
	Name() string
	Usage() string // one-line synopsis without the program name
	Help() string  // multi-line long help
	Run(ctx context.Context, args []string) error
}

// App wires commands together and renders help/errors.
type App struct {
	Name    string
	Summary string
	Out     io.Writer
	Err     io.Writer
	Stdout  io.Writer // alias kept for clarity in tests

	commands []Command
	byName   map[string]Command
}

func NewApp(name, summary string, out, errW io.Writer) *App {
	return &App{
		Name:    name,
		Summary: summary,
		Out:     out,
		Err:     errW,
		byName:  map[string]Command{},
	}
}

// Register adds a command. Later registrations of the same name fail loudly at
// startup rather than silently shadowing.
func (a *App) Register(cmds ...Command) error {
	for _, c := range cmds {
		if _, dup := a.byName[c.Name()]; dup {
			return fmt.Errorf("cli: duplicate command %q", c.Name())
		}
		a.byName[c.Name()] = c
		a.commands = append(a.commands, c)
	}
	return nil
}

func (a *App) Commands() []Command { return a.commands }

// Run dispatches. Exit codes follow convention: 0 success, 1 failure,
// 2 usage error.
func (a *App) Run(ctx context.Context, args []string) int {
	if len(args) == 0 {
		a.PrintUsage(a.Err)
		return 2
	}
	switch args[0] {
	case "-h", "--help", "help":
		a.PrintUsage(a.Out)
		return 0
	}
	cmd, ok := a.byName[args[0]]
	if !ok {
		fmt.Fprintf(a.Err, "%s: unknown command %q\n\n", a.Name, args[0])
		a.PrintUsage(a.Err)
		return 2
	}
	if err := cmd.Run(ctx, args[1:]); err != nil {
		var uerr *UsageError
		if errorsAs(err, &uerr) {
			fmt.Fprintf(a.Err, "%s %s: %s\n\nusage:\n  %s %s\n",
				a.Name, cmd.Name(), uerr.msg, a.Name, cmd.Usage())
			return 2
		}
		fmt.Fprintf(a.Err, "%s %s: %v\n", a.Name, cmd.Name(), err)
		return 1
	}
	return 0
}

// PrintUsage writes the top-level help.
func (a *App) PrintUsage(w io.Writer) {
	fmt.Fprintf(w, "%s — %s\n\n", a.Name, a.Summary)
	fmt.Fprintf(w, "usage:\n  %s <command> [flags]\n\ncommands:\n", a.Name)
	width := 0
	for _, c := range a.commands {
		if l := len(c.Name()); l > width {
			width = l
		}
	}
	for _, c := range a.commands {
		fmt.Fprintf(w, "  %-*s  %s\n", width, c.Name(), firstLine(c.Help()))
	}
	fmt.Fprintf(w, "\nrun '%s <command> --help' for details.\n", a.Name)
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

// UsageError marks argument errors so they render as usage help, not failures.
type UsageError struct{ msg string }

func Usagef(format string, args ...any) *UsageError {
	return &UsageError{msg: fmt.Sprintf(format, args...)}
}

func (u *UsageError) Error() string { return u.msg }

// errorsAs avoids importing errors twice in this file's logic paths.
func errorsAs(err error, target **UsageError) bool {
	for err != nil {
		if u, ok := err.(*UsageError); ok { //nolint:errorlint // tiny local chain walk
			*target = u
			return true
		}
		type unwrapper interface{ Unwrap() error }
		uw, ok := err.(unwrapper) //nolint:errorlint // see above
		if !ok {
			return false
		}
		err = uw.Unwrap()
	}
	return false
}
