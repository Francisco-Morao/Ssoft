from typing import Dict, Set, Mapping
from copy import deepcopy
from Label import Label

class MultiLabel:
    """
    Combines multiple Labels in order to analyze many vulnerabilities at once,
    keeping their flows separate and independent.
    """

    def __init__(self, patterns: Set = None, other: "MultiLabel" = None):
        if other is not None:
            # Copy constructor
            self._labels: Dict = {
                p: Label(label) for p, label in other._labels.items()
            }
        elif patterns is not None:
            # Init from a set of patterns
            self._labels = {p: Label() for p in patterns}
        else:
            # Empty constructor
            self._labels = {}

    def get_labels(self) -> Mapping:
        """
        Returns an immutable view similar to Java's Collections.unmodifiableMap.
        """
        # Shallow immutability: keys → patterns (unchanged), values → Label instances (mutable).
        # This matches Java semantics.
        return dict(self._labels)

    def get_label(self, pattern):
        return self._labels.get(pattern)

    def add_source(self, source_name: str) -> None:
        for p in self._labels:
            if p.isSource(source_name):
                self._labels[p].add_source(source_name)

    def add_sanitizer(self, source_name: str, sanitizer_name: str) -> None:
        for p in self._labels:
            if p.isSanitizer(sanitizer_name) and p.isSource(source_name):
                self._labels[p].add_sanitizer(source_name, sanitizer_name)

    def combine(self, other: "MultiLabel") -> "MultiLabel":
        combined = MultiLabel(other=self)  # copy of self

        for p, other_label in other._labels.items():
            if p not in combined._labels:
                combined._labels[p] = Label()

            combined._labels[p] = combined._labels[p].combine(other_label)

        return combined

    def __repr__(self):
        return f"MultiLabel({self._labels})"
