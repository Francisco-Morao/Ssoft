from typing import Dict, Iterable, Optional

from Label import Label
from Pattern import Pattern


class MultiLabel:
    """Track labels for multiple vulnerability patterns.

    Each pattern has a separate `Label`. Sources and sanitizers may only be
    added to the label for a pattern if that pattern declares the source/
    sanitizer in its `Pattern` object.
    """

    def __init__(self, patterns: Optional[Iterable[Pattern]] = None,
                 initial_labels: Optional[Dict[str, Label]] = None) -> None:
        """Create a MultiLabel.

        - `patterns`: iterable of `Pattern` objects describing known patterns.
        - `initial_labels`: optional mapping pattern_name -> Label to initialize
          the corresponding label. Labels provided are copied to ensure
          independence from the caller.
        """
        self._patterns: Dict[str, Pattern] = {}
        self._labels: Dict[str, Label] = {}

        if patterns:
            for p in patterns:
                name = p.get_vulnerable_name
                self._patterns[name] = p
                # initialize an empty label for each known pattern
                self._labels[name] = Label()

        if initial_labels:
            for name, lbl in initial_labels.items():
                if name in self._patterns:
                    # store a copy to guarantee independence
                    self._labels[name] = lbl.copy()

    def add_pattern(self, pattern: Pattern) -> None:
        """Add a new `Pattern` and an empty label for it (if absent)."""
        name = pattern.get_vulnerable_name
        if name not in self._patterns:
            self._patterns[name] = pattern
            self._labels[name] = Label()

    def patterns(self) -> Iterable[str]:
        """Return the known pattern names."""
        return list(self._patterns.keys())

    def add_source(self, pattern_name: str, source: str, influence_type: object) -> bool:
        """Add a source to the label of `pattern_name`.

        Only adds the source if the corresponding `Pattern` declares the
        `source` in its `get_sources` list. Returns True if added, False if
        rejected (unknown pattern or source not declared for that pattern).
        """
        p = self._patterns.get(pattern_name)
        if p is None:
            return False
        # Pattern uses `get_sources` property (list)
        if source not in p.get_sources:
            return False
        self._labels[pattern_name].add_source(source, influence_type)
        return True

    def add_sanitizer(self, pattern_name: str, sanitizer: str) -> bool:
        """Add a sanitizer to the label of `pattern_name` if the pattern
        declares it. Returns True on success, False otherwise."""
        p = self._patterns.get(pattern_name)
        if p is None:
            return False
        if sanitizer not in p.get_sanitizers:
            return False
        self._labels[pattern_name].add_sanitizer(sanitizer)
        return True

    def get_label(self, pattern_name: str) -> Optional[Label]:
        """Return a deep-independent copy of the Label for `pattern_name`.

        Returns `None` if the pattern is unknown.
        """
        lbl = self._labels.get(pattern_name)
        return lbl.copy() if lbl is not None else None

    def get_sources(self, pattern_name: str):
        lbl = self._labels.get(pattern_name)
        return lbl.sources if lbl is not None else None

    def get_sanitizers(self, pattern_name: str):
        lbl = self._labels.get(pattern_name)
        return lbl.sanitizers if lbl is not None else None

    def labels(self) -> Dict[str, Label]:
        """Return copies of all labels keyed by pattern name."""
        return {n: l.copy() for n, l in self._labels.items()}

    @staticmethod
    def combinor(a: "MultiLabel", b: "MultiLabel") -> "MultiLabel":
        """Combine two MultiLabels into a NEW MultiLabel.

        - Patterns are taken as the union of the two inputs. If the same
          pattern name exists in both, the `Pattern` object from `a` is
          preferred (but this can be adapted).
        - Labels for each pattern are combined using `Label.combinor` when
          present in both; otherwise the existing label is copied.
        """
        # Build union of patterns: prefer a's Pattern when name collision
        combined_patterns = {}
        for name, p in a._patterns.items():
            combined_patterns[name] = p
        for name, p in b._patterns.items():
            if name not in combined_patterns:
                combined_patterns[name] = p

        # Build combined labels
        combined_labels = {}
        for name in combined_patterns.keys():
            la = a._labels.get(name)
            lb = b._labels.get(name)
            if la is not None and lb is not None:
                combined_labels[name] = Label.combinor(la, lb)
            elif la is not None:
                combined_labels[name] = la.copy()
            elif lb is not None:
                combined_labels[name] = lb.copy()
            else:
                combined_labels[name] = Label()

        return MultiLabel(patterns=combined_patterns.values(), initial_labels=combined_labels)
