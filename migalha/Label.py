from copy import deepcopy
from typing import Dict, Set, FrozenSet


class Label:
    """
    Tracks how information from sources flows and which sanitizers
    were applied for one vulnerability pattern.
    """

    def __init__(self, other: "Label" = None):
        if other is None:
            # key - the name of the source
            # value - name of the sanitizers applied to information of that source
            self._flows: Dict[str, Set[str]] = {}
        else:
            self._flows = {src: set(sanitizers) for src, sanitizers in other._flows.items()}

    def add_source(self, source: str) -> None:
        self._flows.setdefault(source, set())

    def add_sanitizer(self, source: str, sanitizer: str) -> None:
        self._flows.setdefault(source, set()).add(sanitizer)

    def get_flows(self) -> Dict[str, FrozenSet[str]]:
        # Returns immutable copies using frozenset
        return {src: frozenset(sanitizers) for src, sanitizers in self._flows.items()}

    def get_sources(self) -> FrozenSet[str]:
        return frozenset(self._flows.keys())

    def get_sanitizers_for(self, source: str) -> FrozenSet[str]:
        return frozenset(self._flows.get(source, set()))

    def combine(self, other: "Label") -> "Label":
        combined = Label(self)  # copy of self
        for src, sanitizers in other._flows.items():
            combined._flows.setdefault(src, set()).update(sanitizers)
        return combined

    def __repr__(self):
        return f"Label({self._flows})"
