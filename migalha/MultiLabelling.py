from typing import Dict, Mapping
from MultiLabel import MultiLabel

class MultiLabelling:
    """
    Represents a mapping from program variable names to MultiLabel objects.
    """

    def __init__(self, initial: Dict[str, MultiLabel] = None):
        if initial is None:
            self._map: Dict[str, MultiLabel] = {}
        else:
            self._map = {name: MultiLabel(other=ml) for name, ml in initial.items()}

    def get(self, name: str) -> MultiLabel:
        # Return NEW empty MultiLabel if name not present — matches Java behavior.
        return self._map.get(name, MultiLabel())

    def set(self, var_name: str, ml: MultiLabel) -> None:
        # Store a *copy* of the provided MultiLabel, same as Java's `new MultiLabel(ml)`.
        self._map[var_name] = MultiLabel(other=ml)

    def contains(self, name: str) -> bool:
        return name in self._map

    def get_all(self) -> Mapping[str, MultiLabel]:
        # Return a shallow copy, matching Java’s unmodifiableMap
        return dict(self._map)

    def __repr__(self):
        return f"MultiLabelling({self._map})"

    def copy(self) -> "MultiLabelling":
        """
        Returns a deep copy of this MultiLabelling.
        All MultiLabel objects are copied.
        """
        return MultiLabelling(initial=self._map)

    def combine(self, other: "MultiLabelling") -> "MultiLabelling":
        """
        Returns a new MultiLabelling where each variable's MultiLabel
        reflects what might have happened if either of the two MultiLabellings hold.
        """
        combined = self.copy()

        for name, other_ml in other._map.items():
            if name in combined._map:
                # Combine MultiLabels for variables present in both
                combined._map[name] = combined._map[name].combine(other_ml)
            else:
                # Variables only in 'other' are copied
                combined._map[name] = MultiLabel(other=other_ml)

        return combined