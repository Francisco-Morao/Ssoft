from typing import Dict, List, Set, Mapping
from MultiLabel import MultiLabel
from Pattern import Pattern
from Label import Label

class Vulnerabilities:
    """
    Stores illegal information flows detected in a program slice,
    grouped by vulnerability name.
    """

    def __init__(self):
        self._vulnerabilities: Dict[str, List["Vulnerabilities.IllegalFlow"]] = {}

    class IllegalFlow:
        def __init__(self, sink_name: str, flows: Dict[str, Set[str]]):
            # flows is already a defensive copy from Label.get_flows()
            self.sink_name = sink_name
            self.flows = flows  # dict[str, frozenset[str]]

        def __repr__(self):
            return f"IllegalFlow(sink={self.sink_name!r}, flows={self.flows})"

        def __str__(self):
            return f"Sink={self.sink_name}, flows={self.flows}"

    def record(self, illegal_ml: MultiLabel, sink_name: str) -> None:
        """
        For each (Pattern, Label) pair inside illegal_ml:
        - group by vulnerability name
        - add an IllegalFlow object with copied flows
        """
        for pattern, label in illegal_ml.get_labels().items():
            vuln_name = pattern.get_name()
            self._vulnerabilities.setdefault(vuln_name, [])
            self._vulnerabilities[vuln_name].append(
                Vulnerabilities.IllegalFlow(sink_name, label.get_flows())
            )

    def get_all(self) -> Mapping[str, List["Vulnerabilities.IllegalFlow"]]:
        """
        Returns a shallow copy to emulate Java's unmodifiableMap.
        """
        return dict(self._vulnerabilities)

    def __repr__(self):
        return f"Vulnerabilities({self._vulnerabilities})"
