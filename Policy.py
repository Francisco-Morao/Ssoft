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
    
    #TODO: implement properly
    def detect_illegal_flows(sink_name: str, multilabel: MultiLabel) -> MultiLabel:
        """
        Given a sink name and a MultiLabel, returns a new MultiLabel that only includes labels
        for patterns where an illegal flow is taking place to the given sink.
        
        An illegal flow occurs when:
        - The pattern has sink_name as a sink
        - The label has sources (information is flowing)
        - At least one source has no sanitizer from the pattern applied
        """
        illegal_multilabel = MultiLabel(patterns=set())
        
        # Iterate through patterns in the multilabel
        for pattern, label in multilabel.labels.items():
            # Check if the sink_name is a sink for this pattern
            if sink_name in pattern.sinks:
                # Check if there's an illegal flow (any source not properly sanitized)
                # has_illegal_flow = False
                # for source, sanitizers in label.flows.items():
                #     # An illegal flow occurs if no sanitizer from the pattern has been applied
                #     # (either no sanitizers at all, or none of the pattern's sanitizers)
                    
                #     # even tho that if there is a sanitizer its always going to be from the pattern
                #     if not sanitizers or not sanitizers.intersection(pattern.sanitizers):
                #         has_illegal_flow = True
                #         break
                
                # If there's an illegal flow, add the pattern and copy its label
                # if has_illegal_flow:

                # Directly copy the flows dictionary to preserve exact label data
                for source, sanitizers in label.flows.items():
                    illegal_multilabel.labels[pattern].flows[source] = sanitizers.copy()
        
        return illegal_multilabel