# Synthetic MCP workspaces

Local implementation on `feat/decoy-environments-siem`, left uncommitted.
`init --profile ai-decoy` now includes an MCP workspace on `127.0.0.1:8002`
alongside the two HTTP listeners. Scaffold-time crypto/rand variation changes
workspace/server names, file names and planted marker values. No runtime
randomisation chooses responses. Generated credentials are never registered or
checked with a provider; use only synthetic markers, never real secrets.

An optional MCP sensor `environment` contains:

```yaml
environment:
  depth_threshold: 4
  files:
    - name: README.md
      content: 'Configuration is in .env.'
    - name: .env
      content: 'API_KEY=synthetic-example-honeytoken'
      token_id: workspace-key
  env:
    - name: API_KEY
      content: synthetic-example-honeytoken
      token_id: workspace-key
  queries:
    'select workspace': 'synthetic row'
```

Declare `workspace-key` in root `honeytokens` with the identical synthetic
value and kind `credential`. The example is illustrative; generate fresh
markers for deployment. Existing `tools`, resources and prompts can coexist;
they cannot shadow the five reserved environment tool names.

All new fields are strictly decoded, including nested entries. An environment
requires `depth_threshold` in 2..32 and at least one declared entry. `files` and
`env` each allow 0..32 entries with unique printable UTF-8 names of 1..128 bytes
(no controls or Unicode format controls), and content of 1..4096 UTF-8 bytes.
`token_id` is optional for files; when present it must name a configured
credential whose exact value occurs in the content. Environment names must also
match `[A-Z_][A-Z0-9_]{0,127}` and **require** a credential token reference.
`queries` allows 0..32 exact printable lookup keys of 1..128 bytes and static
results of 1..4096 UTF-8 bytes. Combined key/name and content bytes cap at 16 KiB.
Tools, including the five built-ins, share the existing 32-tool cap. Encoded
results cap at 16 KiB; content whose JSON representation exceeds that bound
returns a fixed unavailable result. MCP request bodies retain their 256 KiB cap.

| Tool | Argument object | Response data |
| --- | --- | --- |
| `list_files` | `{}` | Sorted declared file names |
| `read_file` | `{"path":".env"}` | Exact declared file content |
| `get_env` | `{"name":"API_KEY"}` | Exact declared synthetic env content |
| `search` | `{"query":"Configuration"}` | Sorted names of declared files whose name or content contains the literal query |
| `run_query` | `{"query":"select workspace"}` | Exact declared query result |

Arguments are bounded lookup data, never filesystem paths, environment names
passed to the OS, SQL, regexes or commands. Unknown names, extra/missing keys,
traversal spellings and nonmatching queries return a fixed not-found result.
No normalization, globbing, shell, real filesystem/environment access, provider
call or network request occurs. `search` returns names, not matching contents.

Each accepted JSON-RPC envelope on an HTTP connection advances `step`. Calls
append tool names after scrubbing and then truncating (128 bytes maximum) to `tool_sequence`, capped
at the first 32 names. Step 257 and later are refused with a fixed protocol
error. State belongs to the server-created connection context, is protected by
a mutex, and dies with the connection; there is no client-selected session ID
or unbounded source table. HTTP idle/read/write timeouts remain active. This is
connection-local observation, not identity tracking across reconnects or proxies.
Existing sensors without `environment` retain their behavior and omit these
observation fields.

MCP-001 observes a request for a declared credential-bearing file/env entry;
MCP-002 observes reaching the configured connection depth (and subsequent
accepted steps); MCP-003 observes write/exec/shell/delete/remove/update/insert/
create-shaped tool names, including unknown tools. Nothing is executed or
written. All three are observe-only even under aggressive severity actions;
older content findings retain their prior response semantics. Rule disabling
and global detection disabling still apply. Catalog mappings use only existing
ATT&CK/ATLAS/OWASP identifiers and are pinned in `frameworks.tsv`.

A later presentation of a planted value produces HT-001. If it comes from the
same peer host after contact with a different sensor, opt-in COR-008 can link
the read observation and replay. Its existing predicate is cross-sensor
contact, not proof that a particular read disclosed that exact token. There is
no same-sensor replay correlation, actor attribution or successful-exfiltration
claim. Tests exercise read then replay across real loopback listeners, including
same-binary worker mode. Marker values are scrubbed before previews/storage;
responses deliberately contain the declared fake values.

`aegismesh demo` performs a canary call, list, `.env` read and fake env read on
one connection. It records eleven observations and eight dry-run proposals,
checks marker redaction and reports MCP-001/002 alongside the AI observation
rules. No external agent, model or service is involved.
