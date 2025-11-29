from typing import Iterable, Dict, List, Optional

from Pattern import Pattern
from MultiLabel import MultiLabel


class Policy:
    """Policy describing which vulnerability patterns are in scope.

    Constructor receives an iterable of `Pattern` objects. The policy
    provides selectors to list which vulnerabilities (pattern names)
    treat a given resource name as a source, sanitizer, or sink.
    """

    def __init__(self, patterns: Optional[Iterable[Pattern]] = None) -> None:
        self._patterns: Dict[str, Pattern] = {}
        if patterns:
            for p in patterns:
                # store by vulnerable name
                self._patterns[p.get_vulnerable_name] = p

    def all_pattern_names(self) -> List[str]:
        """Return a list of all known vulnerability (pattern) names."""
        return list(self._patterns.keys())

    def vulnerabilities_with_source(self, source_name: str) -> List[str]:
        """Return vulnerability names that declare `source_name` as a source."""
        return [name for name, p in self._patterns.items() if p.is_source(source_name)]

    def vulnerabilities_with_sanitizer(self, sanitizer_name: str) -> List[str]:
        """Return vulnerability names that declare `sanitizer_name` as a sanitizer."""
        return [name for name, p in self._patterns.items() if p.is_sanitizer(sanitizer_name)]

    def vulnerabilities_with_sink(self, sink_name: str) -> List[str]:
        """Return vulnerability names that declare `sink_name` as a sink."""
        return [name for name, p in self._patterns.items() if p.is_sink(sink_name)]

    def illegal_flows(self, target_name: str, multilabel: MultiLabel) -> MultiLabel:
        # Build initial_labels for the result: only include labels where
        # the policy pattern declares target_name as a sink and the label
        # in multilabel is non-empty (has sources).
        result_labels = {}

        for pname in multilabel.patterns():
            # Only consider patterns that this policy knows about
            pattern = self._patterns.get(pname)
            if pattern is None:
                # unknown pattern: skip (will be initialized empty by MultiLabel)
                continue

            # If the pattern declares the target as a sink
            if pattern.is_sink(target_name):
                lbl = multilabel.get_label(pname)
                if lbl is not None:
                    # consider illegal flow present if label reports any sources
                    if lbl.sources:
                        result_labels[pname] = lbl.copy()

        # Return a MultiLabel with the same pattern objects as the provided
        # multilabel (so the scope matches), and only the selected labels.
        patterns = [self._patterns[p] for p in multilabel.patterns() if p in self._patterns]
        return MultiLabel(patterns=patterns, initial_labels=result_labels)
