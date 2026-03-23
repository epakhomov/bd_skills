---
name: list_projects
description: List Black Duck projects on the server. Optionally search by name.
argument-hint: "[search query]"
disable-model-invocation: true
---

# List Black Duck Projects

List all projects on the Black Duck server, or search for projects by name.

## Behavior

1. If `$ARGUMENTS` is provided, call `search_projects` with `query` set to `$ARGUMENTS` and `limit: 20`.
2. If `$ARGUMENTS` is empty, call `list_projects` with `limit: 20, offset: 0`.

## Output Format

Display results as a numbered table:

```
## Black Duck Projects (showing X of Y)

| #  | Project Name             | Description          | Created    |
|----|--------------------------|----------------------|------------|
| 1  | my-project               | Some description     | 2025-01-15 |
| 2  | another-project          | —                    | 2025-03-22 |
...
```

- Truncate description to 30 characters, append "..." if truncated. Show "—" if null.
- Format `created_at` as YYYY-MM-DD (date only).
- Number rows starting from `offset + 1`.

## Pagination

After displaying results, if `total_available > total_returned + offset`:
- Show: **"Page X of Y. Say 'more' or 'next' to see the next page."**
- When the user says "more" or "next", call `list_projects` again with `offset` incremented by `limit`.

If all results fit on one page, just show the total count.

## No Results

If zero projects are returned, say: "No projects found." If a search query was used, suggest trying a different term.
