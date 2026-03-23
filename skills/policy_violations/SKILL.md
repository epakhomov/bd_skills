---
name: policy_violations
description: List policy violations for a Black Duck project, grouped by policy.
argument-hint: "<project name>"
disable-model-invocation: true
---

# Black Duck Policy Violations

Show all policy violations for a project, grouped by policy rule.

## Input

`$ARGUMENTS` is the project name (required). If empty, ask the user which project to check.

## Steps

1. Call `list_policy_violations` with `project_name` set to `$ARGUMENTS`.
2. Group the violations by `policy_name`.
3. Display the results.

## Output Format

```
## Policy Violations: <project_name> (version: <version_name>)

**Total: X violations across Y policies**

### <Policy Name> (<severity>) — Z components

| Component           | Version |
|---------------------|---------|
| component-a         | 1.2.3   |
| component-b         | 4.5.6   |

### <Another Policy Name> (<severity>) — Z components

| Component           | Version |
|---------------------|---------|
...
```

- Order policy groups by severity: BLOCKER first, then CRITICAL, MAJOR, MINOR, TRIVIAL.
- Within each group, sort components alphabetically.
- Show the policy description (from the `description` field) as a one-line note under each policy heading.

## No Violations

If there are zero violations, display: "No policy violations found for <project_name> (version: <version_name>)."

## Error Handling

If the project is not found, show the error message and any "did you mean?" suggestions.
