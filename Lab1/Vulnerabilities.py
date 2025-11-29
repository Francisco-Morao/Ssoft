from typing import Dict, List, Optional, Any

from MultiLabel import MultiLabel


class Vulnerabilities:
    """Collect illegal-flow occurrences organized by vulnerability name.

    Each vulnerability name maps to a list of occurrences. An occurrence is
    represented as a dict with keys:
      - 'target': the sink/target name where the illegal flow ends
      - 'multilabel': a copy of the `MultiLabel` describing the flow
      - 'meta': optional additional info (e.g., program location)

    The class stores copies of supplied `MultiLabel` objects to ensure the
    recorded data is independent from caller objects used during analysis.
    """

    def __init__(self) -> None:
        # mapping vulnerability_name -> list[occurrence]
        self._data: Dict[str, List[Dict[str, Any]]] = {}

    def _copy_multilabel(self, ml: MultiLabel) -> MultiLabel:
        """Create an independent copy of a MultiLabel (internal helper).

        This mirrors the copying approach used elsewhere in the project by
        reconstructing a new MultiLabel from the original's internal
        `_patterns` and `_labels` attributes.
        """
        patterns = list(getattr(ml, "_patterns", {}).values())
        labels = getattr(ml, "_labels", {})
        initial_labels = {name: lbl.copy() for name, lbl in labels.items()}
        return MultiLabel(patterns=patterns, initial_labels=initial_labels)

    def add(self, vulnerability_name: str, target: str, multilabel: MultiLabel, meta: Optional[Dict[str, Any]] = None) -> None:
        """Record an illegal-flow occurrence for `vulnerability_name`.

        - `target` is the sink/target name where the illegal flow ended.
        - `multilabel` describes the information that flowed; a copy is
          stored to keep the record independent.
        - `meta` is optional additional information (source location, note, etc.).
        """
        entry = {
            "target": target,
            "multilabel": self._copy_multilabel(multilabel),
            "meta": dict(meta) if meta is not None else None,
        }
        self._data.setdefault(vulnerability_name, []).append(entry)

    def get(self, vulnerability_name: str) -> List[Dict[str, Any]]:
        """Return the list of recorded occurrences for `vulnerability_name`.

        The returned list contains copies of the stored entries (the
        `multilabel` objects are independent copies already), so callers can
        freely inspect or mutate the returned objects without affecting the
        stored state.
        """
        entries = self._data.get(vulnerability_name, [])
        # shallow copy of entries; multilabels are already independent
        return [{"target": e["target"], "multilabel": e["multilabel"], "meta": (dict(e["meta"]) if e["meta"] is not None else None)} for e in entries]

    def all_vulnerabilities(self) -> List[str]:
        """Return the list of vulnerability names that have recorded occurrences."""
        return list(self._data.keys())

    def clear(self) -> None:
        """Clear all recorded vulnerabilities."""
        self._data.clear()

    def count(self, vulnerability_name: Optional[str] = None) -> int:
        """Return number of occurrences recorded for a specific vulnerability,
        or total occurrences if `vulnerability_name` is None."""
        if vulnerability_name is None:
            return sum(len(lst) for lst in self._data.values())
        return len(self._data.get(vulnerability_name, []))

    def to_summary(self) -> Dict[str, List[Dict[str, Any]]]:
        """Return a lightweight summary suitable for reporting.

        The multilabels in the summary are converted to their
        `representative_integrity()` mapping (pattern -> representative type)
        to keep the summary compact and serializable.
        """
        summary: Dict[str, List[Dict[str, Any]]] = {}
        for vname, entries in self._data.items():
            s_entries: List[Dict[str, Any]] = []
            for e in entries:
                ml = e["multilabel"]
                rep = {}
                # attempt to create representative integrity per pattern
                try:
                    for pname in ml.patterns():
                        lbl = ml.get_label(pname)
                        if lbl is not None:
                            rep[pname] = lbl.representative_integrity()
                except Exception:
                    rep = {}

                s_entries.append({"target": e["target"], "representative": rep, "meta": e["meta"]})
            summary[vname] = s_entries
        return summary

    def record_detected_flows(self, target: str, multilabel: MultiLabel, meta: Optional[Dict[str, Any]] = None) -> int:
        """Record illegal-flow occurrences given a `multilabel` that describes
        detected illegal flows to `target`.

        The method inspects the provided `multilabel` and, for each pattern
        that has non-empty sources, records an occurrence for that pattern
        using `add()`. The stored multilabel for each entry contains only
        the pattern's label (to keep records focused and compact) but is a
        deep-independent copy.

        Returns the number of occurrences recorded.
        """
        added = 0
        patterns = getattr(multilabel, "_patterns", {})

        for pname in multilabel.patterns():
            lbl = multilabel.get_label(pname)
            if lbl is None:
                continue
            # consider a detected illegal flow if there are any sources
            if lbl.sources:
                # build a per-pattern multilabel to store (copy of the label)
                if pname in patterns:
                    per_ml = MultiLabel(patterns=[patterns[pname]], initial_labels={pname: lbl.copy()})
                else:
                    per_ml = MultiLabel(patterns=None, initial_labels={pname: lbl.copy()})

                self.add(pname, target, per_ml, meta=meta)
                added += 1

        return added
