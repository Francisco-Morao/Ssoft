#  Develop a class Pattern, that represents a vulnerability pattern, including all its components. It
# should include at least the following basic operations:
# (a) Constructor of a Pattern object, receiving as input a vulnerability name, lists of possible
# source, sanitizer and sink names.
# (b) Selectors for each of its compomnents.
# (c) Tests for checking whether a given name is a source, sanitizer or sink for the pattern.

# --------------> DONE
from dataclasses import dataclass
from typing import Iterable

@dataclass(frozen=True)
class Pattern:
    """
    We use frozen attributes to make the class hashable, allowing it to be used as a dictionary key in MultiLabel.
    """
    vulnerability_name: str
    sources: frozenset[str]
    sinks: frozenset[str]
    sanitizers: frozenset[str]
    implicit_flows: str

    def __init__(
        self,
        vulnerability_name: str,
        sources: Iterable[str],
        sinks: Iterable[str],
        sanitizers: Iterable[str],
        implicit_flows: str
    ) -> None:
        """Initialize a pattern normalizing all collections to frozensets."""
        object.__setattr__(self, 'vulnerability_name', vulnerability_name)
        object.__setattr__(self, 'sources', frozenset(sources))
        object.__setattr__(self, 'sinks', frozenset(sinks))
        object.__setattr__(self, 'sanitizers', frozenset(sanitizers))
        object.__setattr__(self, 'implicit_flows', implicit_flows)

    def is_source(self, item: str) -> bool:
        return item in self.sources

    def is_sanitizer(self, item: str) -> bool:
        return item in self.sanitizers

    def is_sink(self, item: str) -> bool:
        return item in self.sinks
    
    def is_implicit_flow(self) -> bool:
        """Returns whether the pattern allows implicit flows."""
        return self.implicit_flows == "yes"

