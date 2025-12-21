#  Develop a class Pattern, that represents a vulnerability pattern, including all its components. It
# should include at least the following basic operations:
# (a) Constructor of a Pattern object, receiving as input a vulnerability name, lists of possible
# source, sanitizer and sink names.
# (b) Selectors for each of its compomnents.
# (c) Tests for checking whether a given name is a source, sanitizer or sink for the pattern.

# --------------> DONE
from dataclasses import dataclass
from typing import Iterable, Set

@dataclass
class Pattern:

    vulnerability_name: str
    sources: Set[str]
    sinks: Set[str]
    sanitizers: Set[str]

    def __init__(
        self,
        vulnerability_name: str,
        sources: Iterable[str],
        sinks: Iterable[str],
        sanitizers: Iterable[str],
    ) -> None:
        """Initialize a pattern normalizing all collections to sets."""
        self.vulnerability_name = vulnerability_name
        self.sources = set(sources)
        self.sinks = set(sinks)
        self.sanitizers = set(sanitizers)

    def is_source(self, item: str) -> bool:
        return item in self.sources

    def is_sanitizer(self, item: str) -> bool:
        return item in self.sanitizers

    def is_sink(self, item: str) -> bool:
        return item in self.sinks
