package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/metaforismo/aegismesh/internal/console/accounts"
	"github.com/metaforismo/aegismesh/internal/console/audit"
	"github.com/metaforismo/aegismesh/internal/console/tenant"
)

// cliActor identifies offline break-glass changes in the store and audit chain.
const cliActor = "cli:local"

type accountsCmd struct{ env *Env }

// NewAccountsCmd constructs the offline break-glass command for managed console accounts.
func NewAccountsCmd(env *Env) Command { return &accountsCmd{env} }

func (c *accountsCmd) Name() string { return "accounts" }

func (c *accountsCmd) Usage() string {
	return "accounts list|disable|enable|key revoke --state-dir DIR [--local-tenant NAME] [--json] [ACCOUNT_ID [KEY_ID]]"
}

func (c *accountsCmd) Help() string {
	return `Inspect or cut off console-managed accounts offline (break-glass).
Operates directly on <state-dir>/accounts/accounts.json, where --state-dir is the
resolved console.state_dir. Stop the console first: a running console refuses
to overwrite a store changed underneath it and keeps its in-memory sessions.
  accounts list --state-dir DIR [--json]
  accounts disable --state-dir DIR ACCOUNT_ID
  accounts enable --state-dir DIR ACCOUNT_ID
  accounts key revoke --state-dir DIR ACCOUNT_ID KEY_ID
Changes use the console's validation, are recorded as actor cli:local in the
local tenant's audit chain (--local-tenant, default "default"), never print key
material, and skip the last-administrator guard: config-file operators remain
the authoritative recovery path. No account creation or key minting is offered.`
}

func (c *accountsCmd) Run(_ context.Context, args []string) error {
	if len(args) == 0 {
		return Usagef("choose subcommand: list, disable, enable or key revoke")
	}
	if args[0] == "--help" || args[0] == "-h" || args[0] == "help" {
		_, err := fmt.Fprintln(c.env.Out, c.Help())
		return err
	}
	operation := args[0]
	rest := args[1:]
	if operation == "key" {
		if len(rest) == 0 || rest[0] != "revoke" {
			return Usagef("expected key revoke")
		}
		operation, rest = "key revoke", rest[1:]
	}
	fs := newFlagSet("accounts " + operation)
	stateDir := fs.String("state-dir", "", "resolved console state directory")
	localTenant := fs.String("local-tenant", tenant.Default, "local tenant whose audit chain records the change")
	asJSON := fs.Bool("json", false, "emit JSON (list only)")
	if err := fs.Parse(rest); err != nil {
		return Usagef("%v", err)
	}
	if *stateDir == "" {
		return Usagef("--state-dir is required")
	}
	if _, err := tenant.Parse(*localTenant); err != nil {
		return Usagef("--local-tenant must be a tenant slug")
	}
	positional := fs.Args()
	want := map[string]int{"list": 0, "disable": 1, "enable": 1, "key revoke": 2}
	count, known := want[operation]
	if !known {
		return Usagef("unknown subcommand %q", operation)
	}
	if len(positional) != count {
		return Usagef("accounts %s expects %d argument(s)", operation, count)
	}
	if *asJSON && operation != "list" {
		return Usagef("--json applies to list only")
	}
	if count > 0 && !accounts.ValidAccountID(positional[0]) {
		return Usagef("ACCOUNT_ID must look like acc_<16 hex>")
	}
	if count > 1 && !accounts.ValidKeyID(positional[1]) {
		return Usagef("KEY_ID must look like key_<12 hex>")
	}

	// Fixed child names under an operator-supplied directory; nothing else selects paths.
	store, err := accounts.OpenExisting(filepath.Join(*stateDir, "accounts"), accounts.Options{Now: cliNow})
	if err != nil {
		return err
	}
	defer store.Close()
	if operation == "list" {
		return writeAccounts(c.env.Out, store.List(), cliNow(), *asJSON)
	}

	chainDir := filepath.Join(*stateDir, "tenants", *localTenant)
	// Never create tenant state here: that would make a legacy layout look migrated.
	if info, err := os.Lstat(chainDir); err != nil || !info.IsDir() {
		return fmt.Errorf("local audit chain %s not found; refusing an unaudited change", chainDir)
	}
	chain, err := audit.New(chainDir)
	if err != nil {
		return fmt.Errorf("local audit chain unavailable; refusing an unaudited change: %w", err)
	}
	defer chain.Close()
	action, target, detail := "account.update", positional[0], "fields=status source=cli"
	switch operation {
	case "disable", "enable":
		status := accounts.StatusDisabled
		if operation == "enable" {
			status = accounts.StatusActive
		}
		_, _, err = store.Update(positional[0], accounts.Patch{Status: &status}, cliActor, accounts.NoGuard)
	case "key revoke":
		action, target, detail = "key.revoke", positional[1], "account="+positional[0]+" source=cli"
		_, _, err = store.RevokeKey(positional[0], positional[1], cliActor, accounts.NoGuard)
	}
	outcome := "ok"
	if err != nil {
		outcome = "error"
	}
	if auditErr := chain.Append(audit.Record{
		ActorID: cliActor, Actor: "cli", Role: "admin", Action: action, Target: target, Outcome: outcome, Detail: detail,
	}); auditErr != nil {
		return errors.Join(err, fmt.Errorf("audit append failed; inspect the audit chain: %w", auditErr))
	}
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(c.env.Out, "%s %s: ok (restart the console so its sessions reload)\n", operation, target)
	return err
}

type accountListing struct {
	ID         string             `json:"id"`
	Name       string             `json:"name"`
	Kind       string             `json:"kind"`
	Role       string             `json:"role"`
	Status     string             `json:"status"`
	Tenants    []string           `json:"tenants"`
	CreatedAt  time.Time          `json:"created_at"`
	CreatedBy  string             `json:"created_by"`
	LastSeenAt *time.Time         `json:"last_seen_at"`
	Keys       []accounts.KeyView `json:"keys"`
}

func writeAccounts(w io.Writer, list []accounts.Account, now time.Time, asJSON bool) error {
	listings := make([]accountListing, 0, len(list))
	for _, account := range list {
		keys := make([]accounts.KeyView, 0, len(account.Keys))
		for _, key := range account.Keys {
			keys = append(keys, key.View(now))
		}
		listings = append(listings, accountListing{
			ID: account.ID, Name: account.Name, Kind: account.Kind, Role: account.Role, Status: account.Status,
			Tenants: account.Tenants, CreatedAt: account.CreatedAt, CreatedBy: account.CreatedBy,
			LastSeenAt: account.LastSeenAt, Keys: keys,
		})
	}
	if asJSON {
		encoder := json.NewEncoder(w)
		encoder.SetIndent("", "  ")
		return encoder.Encode(map[string]any{"accounts": listings})
	}
	if len(listings) == 0 {
		_, err := fmt.Fprintln(w, "no managed accounts")
		return err
	}
	table := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(table, "ID\tNAME\tKIND\tROLE\tSTATUS\tTENANTS\tACTIVE KEYS")
	keys := 0
	for _, account := range listings {
		active := 0
		for _, key := range account.Keys {
			if key.Status == accounts.KeyActive {
				active++
			}
		}
		keys += len(account.Keys)
		fmt.Fprintf(table, "%s\t%s\t%s\t%s\t%s\t%s\t%d of %d\n", account.ID, account.Name, account.Kind,
			account.Role, account.Status, strings.Join(account.Tenants, ","), active, len(account.Keys))
	}
	if err := table.Flush(); err != nil || keys == 0 {
		return err
	}
	fmt.Fprintln(w)
	table = tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(table, "ACCOUNT\tKEY\tLABEL\tPREFIX\tSTATUS\tEXPIRES")
	for _, account := range listings {
		for _, key := range account.Keys {
			fmt.Fprintf(table, "%s\t%s\t%s\t%s\t%s\t%s\n", account.ID, key.ID, key.Label, key.Prefix, key.Status,
				key.ExpiresAt.Format(time.RFC3339))
		}
	}
	return table.Flush()
}
