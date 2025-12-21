# 3. Develop a class Vulnerabilities, that is used to collect all the illegal flows that are
# discovered during the analysis of the program slice. It should include at least the
# following basic operations:

#   (a) Constructor of a Vulnerabilities object, that enables to collect all the relevant info on the 
# illegal flows that are found, organized according to vulnerability names.

#   (b) Operation that given a multilabel and a name, which represents detected
# illegal flows – the multilabel contains the sources and the sanitizers for the
# patterns for which the name is a sink and the flows are illegal) – saves them
# in a format that enables to report vulnerabilities at the end of the analysis.



# vulnerability: name of vulnerability (string, according to the inputted pattern)

# source: input source (string, according to the inputted pattern, and line where it appears in the code)

# sink: sensitive sink (string, according to the inputted pattern, and line where it appears in the code)

# flows: list of pair (lists with two elements) where the first component is a string "implicit"/"explicit", 
# according to whether the flow includes an implicit flow or not, and the second component, describing 
# the sanitization that the flow has gone through, is a list of pairs (lists with two elements) where the
# first component is a sanitizing functions (string, as in an inputted pattern), and the second component 
# is the line number of where it appears in the code (if no sanitition occurs then the list is empty).


from PROJ.Policy import Policy
from typing import List, Dict, Any, Set, Tuple
from PROJ.Pattern import Pattern
from PROJ.MultiLabel import MultiLabel
from PROJ.Label import Label
from dataclasses import dataclass, field

@dataclass
class Vulnerabilities:
    
    @dataclass
    class Vulnerability:

        vulnerability: str      # comes from pattern.vulnerability_name
        sink: str    # (sink_name, line_number)
        labels: Set[Label] = field(default_factory=set) #represents the source and sanitizers
    
    vulnerabilities: List[Vulnerability] = field(default_factory=list)
    
    def add_vulnerability(self, sink: str, multilabel: MultiLabel) -> None:
        """Given a multilabel and a sink name, saves the illegal flows in the vulnerabilities list."""
        for pattern, label in multilabel.labels.items():
            if pattern.is_sink(sink):
                vulnerability = self.Vulnerability(
                    vulnerability=pattern.vulnerability_name,
                    sink=sink,
                    labels={label}
                )
                self.vulnerabilities.append(vulnerability)

    # TODO Falta esta parte toda do explicit/implicit e sanitizers
    def _extract_flows(self, multilabel: MultiLabel) -> List[List[Any]]:

    def get_output(self) -> List[Any]:
        #TODO: implementar