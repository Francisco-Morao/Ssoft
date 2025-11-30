from typing import List, Set

class Pattern:
    """
    Defines the structure of a vulnerability: what counts as a source,
    sanitizer, and sink.
    """

    def __init__(self, name: str, sources: List[str], sanitizers: List[str], sinks: List[str]):
        self._name = name
        self._sources: Set[str] = set(sources)
        self._sanitizers: Set[str] = set(sanitizers)
        self._sinks: Set[str] = set(sinks)

    def get_name(self) -> str:
        return self._name

    def get_sources(self) -> Set[str]:
        return set(self._sources)

    def get_sanitizers(self) -> Set[str]:
        return set(self._sanitizers)

    def get_sinks(self) -> Set[str]:
        return set(self._sinks)

    def is_source(self, s: str) -> bool:
        return s in self._sources

    def is_sanitizer(self, s: str) -> bool:
        return s in self._sanitizers

    def is_sink(self, s: str) -> bool:
        return s in self._sinks

    def __repr__(self):
        return (f"Pattern(name={self._name!r}, "
                f"sources={self._sources}, "
                f"sanitizers={self._sanitizers}, "
                f"sinks={self._sinks})")
