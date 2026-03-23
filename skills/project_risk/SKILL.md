---
name: project_risk
description: Show the 5-dimensional risk profile for a Black Duck project.
argument-hint: "<project name>"
disable-model-invocation: true
---

# Black Duck Project Risk Profile

Display the 5-dimensional risk profile for a project.

## Input

`$ARGUMENTS` is the project name (required). If empty, ask the user which project to check.

## Steps

1. Call `get_risk_profile` with `project_name` set to `$ARGUMENTS`.
2. Display the resolved version name.
3. Format the risk profile as a table.

## Output Format

```
## Risk Profile: <project_name> (version: <version_name>)

| Risk Dimension  | Critical | High | Medium | Low | OK  |
|-----------------|----------|------|--------|-----|-----|
| Vulnerability   |    X     |  X   |   X    |  X  |  X  |
| License         |    X     |  X   |   X    |  X  |  X  |
| Operational     |    X     |  X   |   X    |  X  |  X  |
| Activity        |    X     |  X   |   X    |  X  |  X  |
| Version         |    X     |  X   |   X    |  X  |  X  |
```

- Bold any cell where the count is > 0 for Critical or High columns.
- After the table, add a one-line summary highlighting the most urgent dimension (the one with the most critical+high counts).

## Error Handling

If the project is not found, show the error message and any "did you mean?" suggestions from the tool response.
