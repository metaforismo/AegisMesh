# AegisMesh periodic observation digest

## Window


```text
"{\"as_of\":\"2026-11-22T12:00:00Z\",\"window\":\"24h\"}"
```

## Totals and preceding window


```text
"{\"new_sources\":1,\"previous_totals\":{\"events\":2,\"interaction\":2,\"canary_invocation\":0,\"correlation_signal\":0,\"sources\":2,\"sensors_active\":1},\"returning_sources\":1,\"totals\":{\"events\":9,\"interaction\":9,\"canary_invocation\":0,\"correlation_signal\":0,\"sources\":2,\"sensors_active\":1}}"
```

## Automation observations


```text
"1"
```

## Top rules


```text
"[{\"title\":\"a credential that exists only in decoy material was presented\",\"rule_id\":\"HT-001\",\"events\":8,\"severity\":\"critical\"},{\"title\":\"interaction followed an instruction embedded in decoy content; consistent with an LLM-driven client\",\"rule_id\":\"AGT-001\",\"events\":1,\"severity\":\"high\"}]"
```

## Newly observed technique relations


```text
"[{\"framework\":\"mitre-atlas\",\"id\":\"AML.T0055\",\"name\":\"Unsecured Credentials\"},{\"framework\":\"mitre-attack\",\"id\":\"T1078\",\"name\":\"Valid Accounts\"},{\"framework\":\"mitre-attack\",\"id\":\"T1552\",\"name\":\"Unsecured Credentials\"},{\"framework\":\"owasp-llm-2025\",\"id\":\"LLM02\",\"name\":\"Sensitive Information Disclosure\"}]"
```

## Planted markers


```text
"{\"agent_canary_hits\":1,\"honeytoken_hits\":8}"
```

## Operator work


```text
"{\"dry_run_recommendations\":3,\"open_investigations\":2}"
```

## Limits


```text
"{\"interpretation\":\"Retained observations, not incidents, client attribution or technique execution; no scheduler or delivery.\",\"history\":\"truncated\",\"scan_truncated\":false,\"source_comparison\":\"New means absent from the preceding sampled window, not first-ever seen.\",\"investigations_available\":true,\"recommendation_excluded\":0,\"recommendation_missing\":0,\"recommendation_cap\":20}"
```

## Snapshot bounds


```text
"{\"index\":{\"events\":13,\"capacity\":100,\"oldest\":\"\",\"history\":\"truncated\"},\"scanned_events\":13,\"scan_limit\":8192,\"scan_truncated\":false}"
```

