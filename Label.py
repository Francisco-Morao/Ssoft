#  Develop a class Label, that represents the integrity of information that is carried by a resource. It
# should capture the sources that might have influenced a certain piece of information, and which
# sanitizers might have intercepted the information since its flow from each source. It should include
# at least the following basic operations:

# (a) Design a structure for the labels. Have in mind that a resource might be influenced by a
# same source in different ways – are your labels refined enough to distinguish the different cases?

# (b) Constructors of a Label object, and operations for adding sources to the label, and
# sanitizers that are intercepting the flows.

# (c) Selectors for each of its components.

# (d) Combinor for returning a new label that represents the integrity of information that
# results from combining two pieces of information.
# Note: Labels must be mutable, which means that the new labels should be independent from
# the original ones.

from dataclasses import dataclass, field
from typing import Dict, Set, Tuple


@dataclass
class Label:

    # information flows from sources to sanitizers
    # it might be influenced by a same source in different ways
    # source -> sanitizers

    # key      the name of the source and the lineno where it is called
    # value    name of the sanitizers applied to information of that source 
    # sets, unlike lists or tuples, cannot have multiple occurrences of the same element and store unordered values.
    flows: Dict[Tuple[str, int], Set[Tuple[str, int]]] = field(default_factory=dict)
    # a cada source pode estar associado um conjunto de sanitizers

    def add_source(self, source: str, lineno):
        """Add a source to the label."""
        
        Tuple_key = (source, lineno)
        
        if Tuple_key not in self.flows:
            self.flows[Tuple_key] = set()
            #empty set of sanitizers for the new source        

    def add_sanitizer(self, sanitizer: str, lineno: int) -> None:
        """Add a sanitizer to all existing flows."""
        for source_key in self.flows.keys():
            print(f"Adding sanitizer '{sanitizer}' to source '{source_key}'")
            self.flows[source_key].add((sanitizer, lineno))

    def combinor(self, other: "Label") -> "Label":
        """ New label that represents the integrity of information that results from combining two pieces of information. """
        """ For the same source in both labels, combine their sanitizers. """

        new_label = Label()

        for source in set(self.flows.keys()).union(other.flows.keys()):
            # get all sources from both labels
            sanitizers_self = self.flows.get(source, set())
            sanitizers_other = other.flows.get(source, set())
            combined_sanitizers = sanitizers_self.union(sanitizers_other)
            # add the combined sanitizers for
            new_label.flows[source] = combined_sanitizers

        return new_label