# Develop a class MultiLabelling, 
# that represents a mapping from variable names to multilabels.

# It should include at least the following basic operations:
# (a) Constructor of a MultiLabelling object, that enables to map variable names to
# multilabels.
# (b) Selectors for returning the multilabel that is assigned to a given name.
# (c) Mutator for updating the multilabel that is assigned to a name.
from copy import deepcopy
from dataclasses import dataclass, field
from typing import Dict
from MultiLabel import MultiLabel

@dataclass
class MultiLabelling:

    """Mapping from variable names to MultiLabel objects."""

    map: Dict[str, MultiLabel]
    
    def get_multilabel(self, var_name: str) -> MultiLabel:
        """Return the MultiLabel assigned to the given variable name."""
        return self.map[var_name]
    
    def mutator(self, var_name: str, multilabel: MultiLabel) -> None:
        self.map[var_name] = multilabel
        
    def copy(self) -> 'MultiLabelling':
        return MultiLabelling(deepcopy(self.map))
    
    def combinor(self, other: "MultiLabelling") -> "MultiLabelling":
        # Combinor for returning a new multilabelling where multilabels associated to names
        # capture what might have happened if either of the multilabellings hold.
        # Only include variables that exist in BOTH branches (conservative approach)
        combined = MultiLabelling({}) 

        # Only combine names that exist in both self and other
        for name in set(self.map.keys()).intersection(other.map.keys()):
            ml_self = self.map[name]
            ml_other = other.map[name]
            combined.map[name] = ml_self.combinor(ml_other)

        return combined 