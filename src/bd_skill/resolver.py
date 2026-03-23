"""
Fuzzy name resolver for Black Duck projects and versions.

When a user-supplied project or version name doesn't exactly match any
known entity, this module provides "did you mean?" suggestions by
ranking all candidates by string similarity using the ``thefuzz`` library
(Levenshtein distance under the hood).
"""

from thefuzz import process


def fuzzy_match(
    query: str,
    candidates: list[str],
    max_results: int = 3,
    threshold: int = 50,
) -> list[str]:
    """Return candidate names similar to *query*, ranked by similarity.

    Args:
        query: The user-supplied name to match against.
        candidates: Known valid names to compare with.
        max_results: Maximum number of suggestions to return.
        threshold: Minimum similarity score (0-100) for a candidate to be
            included.  The default of 50 filters out very poor matches.

    Returns:
        A list of candidate names whose similarity score meets the threshold,
        ordered from best to worst match.
    """
    if not candidates:
        return []
    matches = process.extract(query, candidates, limit=max_results)
    return [name for name, score in matches if score >= threshold]
