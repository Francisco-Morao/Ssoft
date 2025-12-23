# Develop a class MultiLabel that enables your tool to track multiple vulnerabilities at the same time.

# It should generalize the Label class in order to be able to 
#represent distinct labels corresponding to different vulnerability patterns. 

# Include the corresponding constructors, selectors and combinor.

# Have in mind that sources and sanitizers should only be
#  added to labels corresponding to patterns for which that name is a source/sanitizer.

from dataclasses import dataclass
from typing import Dict, Set
from Pattern import Pattern
from Label import Label

@dataclass
class MultiLabel:
    """
    Combines multiple Labels in order to analyze many vulnerabilities at once,
    keeping their flows separate and independent.
    """
    # dictionary where key is pattern and value is a label
    # mutlilabels construct label as they go

    # y.MultiLabel = {
    # XSS  → { input → {html_escape} },
    # SQLi → { input → ∅ }
    # }

    labels: Dict[Pattern, Label]

    def __init__(self, patterns: Set[Pattern], label: Label = None):
        self.labels = dict()
        for pattern in patterns:
            if label is None:
                self.labels[pattern] = Label()
            else:
                self.labels[pattern] = label

    def get_label(self, pattern: Pattern) -> Label:
        """Return the Label assigned to the given pattern."""
        return self.labels[pattern]

    def add_source(self, source_name: str, lineno: int) -> None:
        """Add a source to the appropriate labels.
        When adding a source, ensure it is only added to labels corresponding to patterns"""
        for pattern, label in self.labels.items():
            if pattern.is_source(source_name):
                label.add_source(source_name, lineno)

    def add_sanitizer(self, sanitizer_name: str, lineno: int) -> None:
        """"Add a sanitizer to existing flows where both the source and sanitizer belong to the pattern."""
        for pattern, label in self.labels.items():
            if pattern.is_sanitizer(sanitizer_name):
                # Only add to flows where there is a source (information is flowing)
                label.add_sanitizer(sanitizer_name, lineno)

    # def add_sanitizer_to_all(self, sanitizer_name: str, lineno: int) -> None:
    #     """Add a sanitizer to the appropriate labels. Regardless of source.
    #     When adding a sanitizer, ensure it is only added to labels corresponding to patterns"""
    #     for pattern, label in self.labels.items():
    #         if pattern.is_sanitizer(sanitizer_name):
    #             label.add_sanitizer_to_all(sanitizer_name, lineno)
                
    def add_empty_pattern(self, pattern: Pattern) -> None:
        """Add a pattern with an empty label to the MultiLabel."""
        if pattern not in self.labels:
            self.labels[pattern] = Label()

    def combinor(self, other: "MultiLabel") -> "MultiLabel":
        """Returns a new MultiLabel that combines this MultiLabel with another."""
        """ For each pattern in both MultiLabels, combine their labels. """

        combined = MultiLabel(set()) 

        for pattern in set(self.labels.keys()).union(other.labels.keys()):
            label_self = self.labels.get(pattern)
            label_other = other.labels.get(pattern)

            if label_self and label_other:
                # both MultiLabels have a label for this pattern
                combined.labels[pattern] = label_self.combinor(label_other)
            elif label_self:
                combined.labels[pattern] = label_self
            elif label_other:
                combined.labels[pattern] = label_other

        return combined
