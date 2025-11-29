from typing import Dict, Set, Iterable, Optional
import copy


class Label:
    def __init__(self,
                 sources: Optional[Dict[str, object]] = None,
                 sanitizers: Optional[Iterable[str]] = None) -> None:
        """Construct a Label.

        - `sources` is a dict mapping source -> influence type(s). Influence
          types are normalized to a set of strings for each source.
        - `sanitizers` is an iterable of sanitizer identifiers (stored as a set).
        """
        self._sources: Dict[str, Set[str]] = {}
        if sources:
            for s, t in sources.items():
                self._sources[s] = self._normalize_types(t)

        self._sanitizers: Set[str] = set(sanitizers) if sanitizers is not None else set()

    def _normalize_types(self, typ: object) -> Set[str]:
        """Normalize an influence type to a set of strings.

        Accepts a single string or an iterable of strings.
        """
        if typ is None:
            return set()
        if isinstance(typ, (set, list, tuple)):
            return set(typ)
        return {str(typ)}

    def add_source(self, source: str, influence_type: object) -> None:
        """Add a source with one or more influence types.

        If the source already exists, its influence types are extended.
        """
        types = self._normalize_types(influence_type)
        if source in self._sources:
            self._sources[source].update(types)
        else:
            self._sources[source] = set(types)

    def add_sanitizer(self, sanitizer: str) -> None:
        """Add a sanitizer that intercepts the flow."""
        self._sanitizers.add(sanitizer)

    @property
    def sources(self) -> Dict[str, Set[str]]:
        """Return a copy of sources mapping (source -> set of influence types).

        Returning copies prevents external mutation of internal state.
        """
        return {s: set(types) for s, types in self._sources.items()}

    @property
    def sanitizers(self) -> Set[str]:
        return set(self._sanitizers)

    def copy(self) -> "Label":
        """Return a deep-independent copy of this Label."""
        return Label(sources={s: set(t) for s, t in self._sources.items()}, sanitizers=set(self._sanitizers))

    @staticmethod
    def _influence_rank() -> Dict[str, int]:
        """Ranking of influence types (lower == more trustworthy)."""
        return {"trusted": 0, "indirect": 1, "direct": 2, "tainted": 3}

    @staticmethod
    def _choose_worst(types_set: Set[str]) -> str:
        """Choose the 'worst' (least trustworthy) influence type from a set."""
        rank = Label._influence_rank()
        max_rank = max(rank.values())

        def score(t: str) -> int:
            return rank.get(t, max_rank + 1)

        return max(types_set, key=score)

    @staticmethod
    def combinor(a: "Label", b: "Label") -> "Label":
        """Combine two Labels and return a NEW Label describing the integrity.

        - Sources are combined by taking the union of influence types per source.
        - Sanitizers are combined by union.

        The returned Label is independent (deep copy) from the inputs.
        """
        # Build combined sources (union of influence-type sets)
        new_sources: Dict[str, Set[str]] = {}
        for s, types in a._sources.items():
            new_sources[s] = set(types)
        for s, types in b._sources.items():
            if s in new_sources:
                new_sources[s].update(types)
            else:
                new_sources[s] = set(types)

        # Combined sanitizers
        new_sanitizers = set(a._sanitizers).union(b._sanitizers)

        return Label(sources=new_sources, sanitizers=new_sanitizers)

    def representative_integrity(self) -> Dict[str, Optional[str]]:
        """Return a simplified mapping source -> representative influence type.

        This picks the 'worst' influence type for each source according to
        the configured ranking.
        """
        return {s: (self._choose_worst(types) if types else None) for s, types in self._sources.items()}