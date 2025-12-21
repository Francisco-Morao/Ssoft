#  Develop a class Pattern, that represents a vulnerability pattern, including all its components. It
# should include at least the following basic operations:
# (a) Constructor of a Pattern object, receiving as input a vulnerability name, lists of possible
# source, sanitizer and sink names.
# (b) Selectors for each of its compomnents.
# (c) Tests for checking whether a given name is a source, sanitizer or sink for the pattern.

# --------------> DONE
from dataclasses import dataclass
from typing import Set

@dataclass
class Pattern:

    vulnerability_name: str
    sources: Set[str]
    sinks: Set[str]
    sanitizers: Set[str]

    def is_source(self, item: str) -> bool:
        return item in self.sources

    def is_sanitizer(self, item: str) -> bool:
        return item in self._sanitizers

    def is_sink(self, item: str) -> bool:
        return item in self._sinks
