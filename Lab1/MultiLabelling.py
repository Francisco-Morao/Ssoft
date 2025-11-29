from typing import Dict, Iterable, Optional, List

from MultiLabel import MultiLabel


class MultiLabelling:
    """Map variable names to `MultiLabel` objects.

    Stored multilabels are copies of the provided objects to ensure
    independence. Accessors return copies as well.
    """

    def __init__(self, mapping: Optional[Dict[str, MultiLabel]] = None) -> None:
        """Construct a MultiLabelling.

        `mapping` is an optional dict variable_name -> MultiLabel. Each
        provided MultiLabel is copied before storage to guarantee
        independence from the caller.
        """
        self._store: Dict[str, MultiLabel] = {}
        if mapping:
            for name, ml in mapping.items():
                self._store[name] = self._copy_multilabel(ml)

    def _copy_multilabel(self, ml: MultiLabel) -> MultiLabel:
        """Create an independent copy of a MultiLabel.

        The `MultiLabel` implementation in this workspace keeps pattern
        objects in an attribute named `_patterns` and labels in `_labels`.
        We rely on those to recreate an independent MultiLabel. This
        function performs a safe copy of patterns and label contents.
        """
        # Access the internal pattern objects and label mapping directly
        patterns = list(getattr(ml, "_patterns", {}).values())
        labels = getattr(ml, "_labels", {})
        # initial_labels expects mapping name->Label; labels are Label objects
        initial_labels = {name: lbl.copy() for name, lbl in labels.items()}
        return MultiLabel(patterns=patterns, initial_labels=initial_labels)

    def names(self) -> List[str]:
        """Return a list of variable names that have a multilabel assigned."""
        return list(self._store.keys())

    def get_multilabel(self, var_name: str) -> Optional[MultiLabel]:
        """Return an independent copy of the MultiLabel assigned to `var_name`.

        Returns `None` if `var_name` has no assigned multilabel.
        """
        ml = self._store.get(var_name)
        return self._copy_multilabel(ml) if ml is not None else None

    def set_multilabel(self, var_name: str, multilabel: MultiLabel) -> None:
        """Assign or replace the MultiLabel for `var_name`.

        The stored value is a copy of the provided `multilabel` to keep
        values independent.
        """
        self._store[var_name] = self._copy_multilabel(multilabel)

    def update_multilabel(self, var_name: str, multilabel: MultiLabel) -> bool:
        """Update an existing multilabel for `var_name`.

        If `var_name` is present, replace its multilabel with a copy of the
        provided `multilabel` and return True. If not present, return False.
        """
        if var_name not in self._store:
            return False
        self._store[var_name] = self._copy_multilabel(multilabel)
        return True

    def remove(self, var_name: str) -> bool:
        """Remove a variable mapping. Returns True if removed, False if absent."""
        return self._store.pop(var_name, None) is not None

    def deepcopy(self) -> "MultiLabelling":
        """Return a deep copy of this MultiLabelling.

        Each stored `MultiLabel` is copied so the returned
        `MultiLabelling` is fully independent from the original.
        """
        mapping = {name: self._copy_multilabel(ml) for name, ml in self._store.items()}
        return MultiLabelling(mapping=mapping)

    def __deepcopy__(self, memo):
        """Support for the `copy.deepcopy` protocol."""
        return self.deepcopy()

    @staticmethod
    def combinor(a: "MultiLabelling", b: "MultiLabelling") -> "MultiLabelling":
        """Combine two MultiLabellings into a NEW MultiLabelling.

        - Variable names are taken as the union of the two inputs.
        - For each variable present in both inputs, the corresponding
          `MultiLabel.combinor` is used to produce a new `MultiLabel` that
          captures what might have happened if either multilabelling held.
        - If a variable is present only in one input, its multilabel is
          copied into the result.
        """
        combined_mapping = {}
        # union of names
        names = set(a._store.keys()).union(b._store.keys())
        for name in names:
            ma = a._store.get(name)
            mb = b._store.get(name)
            if ma is not None and mb is not None:
                combined_mapping[name] = MultiLabel.combinor(ma, mb)
            elif ma is not None:
                combined_mapping[name] = a._copy_multilabel(ma)
            else:
                combined_mapping[name] = b._copy_multilabel(mb)

        return MultiLabelling(mapping=combined_mapping)
