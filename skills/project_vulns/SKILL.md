---
name: project_vulns
description: List vulnerable components in a Black Duck project, with severity summary.
argument-hint: "<project name> [critical|high|medium|low]"
disable-model-invocation: true
---

# Black Duck Vulnerable Components

Show vulnerability summary and list vulnerable components for a project.

## Input

`$ARGUMENTS` contains the project name, optionally followed by a severity filter.

Parse `$ARGUMENTS`:
- If the last word is one of `critical`, `high`, `medium`, `low` (case-insensitive), use it as the severity filter and the rest as the project name.
- Otherwise, use the entire string as the project name with no severity filter.

If `$ARGUMENTS` is empty, ask the user which project to check.

## Steps

1. Call `count_vulnerabilities` with the project name (and severity filter if provided) to get summary counts.
2. Call `list_vulnerable_components` with the project name, `limit: 20` (and severity filter if provided).
3. Display both results.

## Output Format

```
## Vulnerabilities: <project_name> (version: <version_name>)

### Summary
| Critical | High | Medium | Low | Total |
|----------|------|--------|-----|-------|
|    X     |  X   |   X    |  X  |   X   |

### Vulnerable Components (showing X of Y)

| Component           | Version | Severity | Vuln ID         | Status |
|---------------------|---------|----------|-----------------|--------|
| log4j-core          | 2.14.1  | CRITICAL | CVE-2021-44228  | NEW    |
...
```

- Bold CRITICAL and HIGH severity values.
- If there are more results than displayed, show: **"Showing 20 of Y. Say 'more' to see the next page."**

## Error Handling

If the project is not found, show the error message and any "did you mean?" suggestions.
