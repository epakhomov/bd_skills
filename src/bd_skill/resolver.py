from thefuzz import process


def fuzzy_match(
    query: str,
    candidates: list[str],
    max_results: int = 3,
    threshold: int = 50,
) -> list[str]:
    """Return candidate names similar to query, ranked by similarity."""
    if not candidates:
        return []
    matches = process.extract(query, candidates, limit=max_results)
    return [name for name, score in matches if score >= threshold]
