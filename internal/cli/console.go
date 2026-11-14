package cli

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/metaforismo/aegismesh/internal/console/auth"
)

type consoleCmd struct{ env *Env }

// NewConsoleCmd constructs the local operator token generation and hashing command.
func NewConsoleCmd(env *Env) Command {
	return &consoleCmd{env}
}

// Name returns the command name used by the CLI router.
func (c *consoleCmd) Name() string {
	return "console"
}

// Usage describes the supported local credential commands.
func (c *consoleCmd) Usage() string {
	return "console token | console hash"
}

// Help explains bounded credential input and safe token handling.
func (c *consoleCmd) Help() string {
	return `Generate a console operator token or hash one from stdin.
console token prints a new cryptographically random token exactly once and a
ready-to-paste operators snippet (default name alice, role admin). Protect the
token as a password. The config contains only its SHA-256 digest.
console hash reads at most 4096 bytes from stdin, trims surrounding whitespace,
and prints only its SHA-256. Tokens are never accepted as command arguments.`
}

// Run generates a token or hashes a bounded token read from stdin.
func (c *consoleCmd) Run(_ context.Context, args []string) error {
	if len(args) == 1 && (args[0] == "--help" || args[0] == "-h") {
		_, err := fmt.Fprintln(c.env.Out, c.Help())
		return err
	}

	if len(args) != 1 {
		return Usagef("expected token or hash")
	}

	switch args[0] {
	case "token":
		token, err := auth.Token()
		if err != nil {
			return err
		}
		return writeConsoleToken(c.env.Out, token)
	case "hash":
		if c.env.Stdin == nil {
			return Usagef("stdin is required")
		}
		input, err := io.ReadAll(io.LimitReader(c.env.Stdin, 4097))
		if err != nil {
			return err
		}
		if len(input) > 4096 {
			return Usagef("token input exceeds 4096 bytes")
		}
		token := strings.TrimSpace(string(input))
		if token == "" {
			return Usagef("stdin token is empty")
		}
		_, err = fmt.Fprintln(c.env.Out, auth.Digest(token))
		return err
	default:
		return Usagef("expected token or hash")
	}
}

func writeConsoleToken(w io.Writer, token string) error {
	const format = "token (save now): %s\n\noperators:\n" +
		"  - name: alice\n    role: admin\n    token_sha256: \"%s\"\n"
	_, err := fmt.Fprintf(w, format, token, auth.Digest(token))
	return err
}
