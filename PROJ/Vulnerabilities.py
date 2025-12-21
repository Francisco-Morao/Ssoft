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



# <OUTPUT> ::= [ <VULNERABILITIES> ]
# <VULNERABILITIES> := "none" | <VULNERABILITY> | <VULNERABILITY>, <VULNERABILITIES>
# <VULNERABILITY> ::= { "vulnerability": "<STRING>",
#                     "source": [ "<STRING>", <INT> ]
#                     "sink": [ "<STRING>", <INT> ],
#                     "flows": [ <FLOWS> ] }
# <FLOWS> ::= <FLOW> | <FLOW>, <FLOWS>
# <FLOW> ::= [ <IMPEXP>, [] ] | [ <IMPEXP>, [<SANITIZERS>] ]
# <IMPEXP> ::= "implicit" | "explicit"
# <SANITIZERS> ::= <SANITIZER> | <SANITIZER>, <SANITIZERS>
# <SANITIZER> ::= [ <STRING>, <INT> ]


from PROJ.Policy import Policy
from typing import List, Dict, Any, Tuple
from PROJ.Pattern import Pattern
from PROJ.MultiLabel import MultiLabel
from dataclasses import dataclass, field

@dataclass
class Vulnerabilities:
    
    @dataclass
    class Vulnerability:
        vulnerability: str
        source: Tuple[str, int]
        sink: Tuple[str, int]
        flows: List[List[Any]]  # List of flows, each flow is [IMPEXP, [SANITIZERS]] ??????????????
    
    vulnerabilities: List[Vulnerability] = field(default_factory=list)
    vulnerabilities_by_name: Dict[str, List[Vulnerability]] = field(default_factory=dict) # TODO NOS PRECISAMOS MESMO DISTO?
    
    def add_vulnerability(self, multilabel: MultiLabel, sink_name: str, 
                         source: Tuple[str, int], sink: Tuple[str, int]):

        # Extract flows from the multilabel
        flows = self._extract_flows(multilabel)
        
        # Create vulnerability entry
        vulnerability = self.Vulnerability(
            vulnerability=sink_name,
            source=source,
            sink=sink,
            flows=flows
        )
        
        # Add to organized structure
        if sink_name not in self.vulnerabilities_by_name:
            self.vulnerabilities_by_name[sink_name] = []
        
        self.vulnerabilities_by_name[sink_name].append(vulnerability)
        self.vulnerabilities.append(vulnerability)
    
    # TODO Falta esta parte toda do explicit/implicit e sanitizers
    def _extract_flows(self, multilabel: MultiLabel) -> List[List[Any]]:

        flows = []
        
        # Iterate through each pattern's label in the multilabel
        for pattern, label in multilabel.labels.items():
            # Get flows from the label (source -> set of sanitizers)
            label_flows = label.flows()
            
            for source, sanitizers in label_flows.items():
                flow_entry = [source, sanitizers]
                flows.append(flow_entry)
        return flows
    
    def get_output(self) -> List[Any]:

        if not self.vulnerabilities:
            return []
        
        output = []
        for vulnerability in self.vulnerabilities:
            output.append({
                "vulnerability": vulnerability.vulnerability,
                "source": [vulnerability.source[0], vulnerability.source[1]],
                "sink": [vulnerability.sink[0], vulnerability.sink[1]],
                "flows": vulnerability.flows
            })
        
        return output
    
    def get_by_name(self, vulnerability_name: str) -> List[Vulnerability]:

        return self.vulnerabilities_by_name.get(vulnerability_name, [])
        
        