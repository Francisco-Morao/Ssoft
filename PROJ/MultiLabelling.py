# Develop a class MultiLabelling, 
# that represents a mapping from variable names to multilabels.

# It should include at least the following basic operations:
# (a) Constructor of a MultiLabelling object, that enables to map variable names to
# multilabels.
# (b) Selectors for returning the multilabel that is assigned to a given name.
# (c) Mutator for updating the multilabel that is assigned to a name.
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