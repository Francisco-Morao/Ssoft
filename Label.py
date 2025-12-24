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
from typing import Dict, Set, Tuple, FrozenSet, List


@dataclass
class Label:

    # information flows from sources to sanitizers
    # it might be influenced by a same source in different ways
    # source -> sanitizers

    # Changed structure to support multiple flows from the same source with different sanitizers
    # Each flow is represented as (source, frozenset of sanitizers) to allow for distinct paths
    flows: List[Tuple[Tuple[str, int], FrozenSet[Tuple[str, int]]]] = field(default_factory=list)
    # Each source can have multiple flows with different sanitizer sets

    def add_source(self, source: str, lineno):
        """Add a source to the label as a new flow with no sanitizers."""
        flow = ((source, lineno), frozenset())
        if flow not in self.flows:
            self.flows.append(flow)        

    def add_sanitizer(self, sanitizer: str, lineno: int) -> None:
        """Add a sanitizer to all existing flows."""
        new_flows = []
        for source, sanitizers in self.flows:
            # Union the new sanitizer with existing ones
            new_sanitizers = frozenset(sanitizers | {(sanitizer, lineno)})
            new_flows.append((source, new_sanitizers))
        self.flows = new_flows

    def combinor(self, other: "Label") -> "Label":
        """ New label that represents the integrity of information that results from combining two pieces of information. """
        """ Includes all flows from both labels, preserving distinct sanitization paths. """

        new_label = Label()
        
        # Add all flows from self
        for flow in self.flows:
            if flow not in new_label.flows:
                new_label.flows.append(flow)
        
        # Add all flows from other
        for flow in other.flows:
            if flow not in new_label.flows:
                new_label.flows.append(flow)

        return new_label

    def copy_with_updated_lines(self, source_name: str, new_lineno: int) -> "Label":
        """Create a copy of this label, updating line numbers for flows matching source_name.
         Used when traversing AST nodes to set correct line numbers."""
        new_label = Label()
        for src, sanitizers in self.flows:
            if src[0] == source_name and len(sanitizers) == 0:
                # Update the line number for direct source flows (no sanitizers)
                new_label.flows.append(((src[0], new_lineno), sanitizers))
            else:
                # Keep the original flow as-is
                new_label.flows.append((src, sanitizers))
        return new_label

    def add_flow(self, source: str, lineno: int, sanitizers: FrozenSet[Tuple[str, int]] = None) -> None:
        """Add a flow to the label. If the flow already exists, it won't be duplicated."""
        if sanitizers is None:
            sanitizers = frozenset()
        flow = ((source, lineno), sanitizers)
        if flow not in self.flows:
            self.flows.append(flow)
    
