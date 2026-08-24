package cli

import (
	"context"
	"fmt"
	"strings"
)

type completionCmd struct {
	env *Env
}

func newCompletionCmd(env *Env) *completionCmd { return &completionCmd{env: env} }

func (c *completionCmd) Name() string  { return "completion" }
func (c *completionCmd) Usage() string { return "completion [bash|zsh|fish]" }
func (c *completionCmd) Help() string {
	return `Emit a shell completion script for the given shell.

Install, e.g.:
  bash: source <(aegismesh completion bash)   # or into ~/.bashrc
  zsh:  aegismesh completion zsh > ~/.zfunc/_aegismesh
  fish: aegismesh completion fish > ~/.config/fish/completions/aegismesh.fish`
}

var knownCommands = []string{"init", "doctor", "healthcheck", "validate", "run", "inspect", "recommend", "rules", "migrate", "version", "completion", "ext"}

func (c *completionCmd) Run(_ context.Context, args []string) error {
	if len(args) != 1 {
		return Usagef("choose a shell: bash, zsh, or fish")
	}
	switch args[0] {
	case "bash":
		fmt.Fprint(c.env.Out, bashScript)
	case "zsh":
		fmt.Fprint(c.env.Out, zshScript)
	case "fish":
		fmt.Fprint(c.env.Out, fishScript)
	default:
		return Usagef("unknown shell %q (want bash|zsh|fish)", args[0])
	}
	return nil
}

var bashScript = `# aegismesh bash completion
_aegismesh_completions() {
  local cur="${COMP_WORDS[COMP_CWORD]}"
  local prev="${COMP_WORDS[COMP_CWORD-1]}"
  local cmds="` + strings.Join(knownCommands, " ") + `"
  if [ "$COMP_CWORD" -eq 1 ]; then
    COMPREPLY=( $(compgen -W "$cmds" -- "$cur") )
    return
  fi
  case "${COMP_WORDS[1]}" in
    inspect)
      if [ "$COMP_CWORD" -eq 2 ]; then
        COMPREPLY=( $(compgen -W "list show export" -- "$cur") )
      else
        case "$prev" in
          --data-dir) COMPREPLY=( $(compgen -d -- "$cur") ) ;;
          *) COMPREPLY=( $(compgen -W "--data-dir --limit --sensor --kind --verify --id --out --json" -- "$cur") ) ;;
        esac
      fi ;;
    recommend)
      case "$prev" in
        --data-dir) COMPREPLY=( $(compgen -d -- "$cur") ) ;;
        --classification) COMPREPLY=( $(compgen -W "interaction canary_invocation correlation_signal" -- "$cur") ) ;;
        --rule) COMPREPLY=( $(compgen -W "PI-001 PI-002 EXF-001 ESC-001 OBS-001 RES-001 COR-001 COR-002 COR-003 COR-004" -- "$cur") ) ;;
        *) COMPREPLY=( $(compgen -W "--data-dir --limit --rule --sensor --classification --json" -- "$cur") ) ;;
      esac ;;
    migrate)
      if [ "$COMP_CWORD" -eq 2 ]; then COMPREPLY=( $(compgen -W "beelzebub" -- "$cur") )
      else COMPREPLY=( $(compgen -W "--out --write --force --json" -- "$cur") ); fi ;;
    run|validate|doctor)
      COMPREPLY=( $(compgen -W "--config --dry-run --json -o" -- "$cur"); compgen -f -X '!*.yaml' -- "$cur" >/dev/null 2>&1 && true ) ;;
    init)
      COMPREPLY=( $(compgen -W "--dir --force --json" -- "$cur"); true ) ;;
    version) COMPREPLY=( $(compgen -W "--json" -- "$cur") ) ;;
    completion) COMPREPLY=( $(compgen -W "bash zsh fish" -- "$cur") ) ;;
  esac
}
complete -F _aegismesh_completions aegismesh
`

var zshScript = `#compdef aegismesh
# aegismesh zsh completion
_aegismesh() {
  local -a commands
  commands=(
` + zshCommandList() + `  )
  _arguments -C \
    '1: :->cmds' \
    '*:: :->args'
  case $state in
    cmds) _describe 'command' commands ;;
    args)
      case $words[1] in
        inspect) _values 'subcommand' list show export ;;
        recommend) _arguments \
          '--data-dir[evidence directory]:directory:_directories' \
          '--limit[maximum recommendations]:number:' \
          '--rule[exact rule id]:rule id:' \
          '--sensor[exact sensor id]:sensor id:' \
          '--classification[evidence class]:class:(interaction canary_invocation correlation_signal)' \
          '--json[emit JSON output]' ;;
        migrate) _values 'target' beelzebub ;;
        completion) _values 'shell' bash zsh fish ;;
      esac ;;
  esac
}
_aegismesh "$@"
`

func zshCommandList() string {
	var sb strings.Builder
	for _, c := range knownCommands {
		sb.WriteString("    '" + c + "[command]'\n")
	}
	return sb.String()
}

var fishScript = `# aegismesh fish completion
complete -c aegismesh -n '__fish_use_subcommand' -a '` + strings.Join(knownCommands, "' '") + `'
complete -c aegismesh -n '__fish_seen_subcommand_from inspect; and __fish_is_first_arg' -a 'list show export'
complete -c aegismesh -n '__fish_seen_subcommand_from migrate; and __fish_is_first_arg' -a 'beelzebub'
complete -c aegismesh -n '__fish_seen_subcommand_from completion' -a 'bash zsh fish'
complete -c aegismesh -n '__fish_seen_subcommand_from recommend' -l data-dir -r -d 'evidence directory'
complete -c aegismesh -n '__fish_seen_subcommand_from recommend' -l limit -r -d 'maximum recommendations'
complete -c aegismesh -n '__fish_seen_subcommand_from recommend' -l rule -r -d 'exact rule id'
complete -c aegismesh -n '__fish_seen_subcommand_from recommend' -l sensor -r -d 'exact sensor id'
complete -c aegismesh -n '__fish_seen_subcommand_from recommend' -l classification -r -a 'interaction canary_invocation correlation_signal' -d 'evidence class'
complete -c aegismesh -n '__fish_seen_subcommand_from recommend' -l json -d 'JSON output'
complete -c aegismesh -l config -r -d 'config file'
complete -c aegismesh -l data-dir -r -d 'evidence directory'
complete -c aegismesh -l json -d 'JSON output'
complete -c aegismesh -l dry-run -d 'bind and stop immediately'
`
