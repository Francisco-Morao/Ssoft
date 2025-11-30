from typing import Set
from Pattern import Pattern
from MultiLabel import MultiLabel
from Label import Label

class Policy:
    """
    Represents an information-flow policy built from a set of vulnerability
    patterns, responsible for determining which flows are illegal.
    """

    def __init__(self, patterns: Set[Pattern]):
        # Defensive copy, same as Java: new HashSet<>(patterns)
        self._patterns: Set[Pattern] = set(patterns)

    def get_vulnerabilities_with_source(self, source: str) -> Set[str]:
        result = set()
        for p in self._patterns:
            if p.is_source(source):
                result.add(p.get_name())
        return result

    def get_vulnerabilities_with_sanitizer(self, sanitizer: str) -> Set[str]:
        result = set()
        for p in self._patterns:
            if p.is_sanitizer(sanitizer):
                result.add(p.get_name())
        return result

    def get_vulnerabilities_with_sink(self, sink: str) -> Set[str]:
        result = set()
        for p in self._patterns:
            if p.is_sink(sink):
                result.add(p.get_name())
        return result

    def detect_illegal_flows(self, name: str, multi_label: MultiLabel) -> MultiLabel:
        """
        Mirrors Java behavior exactly:

        For every pattern P associated with the MultiLabel input:
        - If P considers `name` to be a sink → copy the label for that pattern
          into a new MultiLabel object of illegal flows.
        """
        illegal = MultiLabel()

        for p in multi_label.get_labels().keys():
            if p.is_sink(name):
                label_copy = Label(multi_label.get_label(p))
                # equivalent to: illegal.getLabels().put(p, copy)
                illegal._labels[p] = label_copy

        return illegal

    def __repr__(self):
        return f"Policy(patterns={self._patterns})"
