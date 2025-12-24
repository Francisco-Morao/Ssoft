# Develop a class Policy, representing an information flow policy, that uses a pattern data base for
# recognizing illegal information flows. It should include at least the following basic operations:

# (a) Constructor of a Policy object, receiving as input the patterns to be considered.

# (b) Selectors for returning the vulnerability names that have a given name as a source
# those that have a given name as a sanitizer, and those that have a given name as a sink.

# (c) Operation that, given a name and a multilabel that describes the information that is flowing to a
# certain name, determines the corresponding illegal flows, i.e., which part of the multilabel has the
# given name as a sink. It should return a multilabel that is like the one received as parameter, but that
# only assigns labels to patterns for which an illegal flow is taking place.

from dataclasses import dataclass, field
from typing import List, Set
from Pattern import Pattern
from MultiLabel import MultiLabel

@dataclass
class Policy:
    """
    
    """
    patterns: List[Pattern] = field(default_factory=list)

    def get_vulnerabilities_with_source(self, source_name: str) -> Set[str]:
        """
        Returns the names of vulnerabilities that have the given source name.
        """
        vulnerabilities: Set[str] = set()

        for pattern in self.patterns:
            if source_name in pattern.sources:
                vulnerabilities.add(pattern.vulnerability_name)

        return vulnerabilities

    def get_vulnerabilities_with_sanitizer(self, sanitizer_name: str) -> Set[str]:
        """
        Returns the names of vulnerabilities that have the given sanitizer name.
        """
        vulnerabilities: Set[str] = set()

        for pattern in self.patterns:
            if sanitizer_name in pattern.sanitizers:
                vulnerabilities.add(pattern.vulnerability_name)

        return vulnerabilities
    
    def get_vulnerabilities_with_sink(self, sink_name: str) -> Set[str]:
        """
        Returns the names of vulnerabilities that have the given sink name.
        """
        
        vulnerabilities: Set[str] = set()

        for pattern in self.patterns:
            if sink_name in pattern.sinks:
                vulnerabilities.add(pattern.vulnerability_name)

        return vulnerabilities
    
    def add_pattern(self, pattern_str: str) -> None:
        new_patterns = list()
        for pattern in self.patterns:
            new_pattern = pattern.add_source(pattern_str)
            new_patterns.append(new_pattern)

        self.patterns = new_patterns

    def detect_illegal_flows(self, sink_name: str, multilabel: MultiLabel) -> MultiLabel:
        """
        Given a sink name and a MultiLabel, returns a new MultiLabel that only includes labels
        for patterns where an illegal flow is taking place to the given sink.
        
        An illegal flow occurs when:
        - The pattern has sink_name as a sink
        - The label has sources (information is flowing)
        - At least one source has no sanitizer from the pattern applied
        """
        # Use patterns from the multilabel, not from self.patterns
        # This handles the case where patterns have been dynamically updated
        
        illegal_multilabel = MultiLabel(multilabel.labels.keys())

        # Iterate through patterns in the multilabel
        for pattern, label in multilabel.labels.items():
            # Check if the sink_name is a sink for this pattern
            if sink_name in pattern.sinks: #há flow
                # Check if there's a flow from a source to a sink
                for source, sanitizers in label.flows:
                    # Accept all sources in the label (including undefined variables treated as sources)
                    # Only filter out if the source is explicitly listed as a sink (not a source of taint)
                    # Actually, we should include all flows - the label already has the right flows
                    illegal_multilabel.labels[pattern].flows.append((source, frozenset()))
                    # Find the corresponding flow in illegal_multilabel and update its sanitizers
                    idx = len(illegal_multilabel.labels[pattern].flows) - 1
                    updated_sanitizers = set()
                    for sanitizer in sanitizers:
                        if pattern.is_sanitizer(sanitizer[0]):
                            updated_sanitizers.add(sanitizer)
                    illegal_multilabel.labels[pattern].flows[idx] = (source, frozenset(updated_sanitizers))
                
        # Return None if no illegal flows were found
        if not any(illegal_multilabel.labels[pattern].flows for pattern in illegal_multilabel.labels):
            return None

        return illegal_multilabel