# 3. Develop a class Vulnerabilities, that is used to collect all the illegal flows that are
# discovered during the analysis of the program slice. It should include at least the
# following basic operations:

#   (a) Constructor of a Vulnerabilities object, that enables to collect all the relevant info on the 
# illegal flows that are found, organized according to vulnerability names.

#   (b) Operation that given a multilabel and a name, which represents detected
# illegal flows – the multilabel contains the sources and the sanitizers1 for the
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


from typing import List, Set, Tuple, Any
from MultiLabel import MultiLabel
from Label import Label
from dataclasses import dataclass, field

@dataclass
class Vulnerabilities:
    
    @dataclass
    class Vulnerability:

        vulnerability: str      # comes from pattern.vulnerability_name
        sink: Tuple[str, int]    # (sink_name, line_number)
        labels: List[Label] = field(default_factory=list) #represents the source and sanitizers
    
    vulnerabilities: List[Vulnerability] = field(default_factory=list)
    
    def add_vulnerability(self, sink: str, multilabel: MultiLabel, sink_lineno: int) -> None:
        """Given a multilabel and a sink name, saves the illegal flows in the vulnerabilities list."""
        for pattern, label in multilabel.labels.items():
            if pattern.is_sink(sink):
                vulnerability = self.Vulnerability(
                    vulnerability=pattern.vulnerability_name,
                    sink= (sink, sink_lineno),
                    labels=[label]
                )
                self.vulnerabilities.append(vulnerability)

    def check_repetition(self, vulnerability: 'Vulnerabilities.Vulnerability') -> bool:
        """Check if a vulnerability is already recorded."""
        for existing_vuln in self.vulnerabilities:
            if (existing_vuln.vulnerability == vulnerability.vulnerability and
                existing_vuln.sink == vulnerability.sink and
                existing_vuln.labels == vulnerability.labels):
                return True
        return False

    def as_output(self, flow_type: str) -> List[Any]:
        """Returns the vulnerabilities in the specified output format."""
        
        if not self.vulnerabilities:
            return ["none"]

        output = []
        
        # Dictionary to track counters for each vulnerability type
        vulnerability_counters = {}

        for vulnerability in self.vulnerabilities:
            # Get or initialize counter for this vulnerability type
            vuln_name = vulnerability.vulnerability
            if vuln_name not in vulnerability_counters:
                vulnerability_counters[vuln_name] = 1
            
            # Each label represents one source with its sanitizers
            for label in vulnerability.labels:
                # Each source in the label.flows represents a different flow path
                for source_tuple, sanitizers_tuples in label.flows.items():
                    # Convert sanitizers set to list of [sanitizer_name, line_number] pairs
                    sanitizers_list = [[sanitizer[0], sanitizer[1]] for sanitizer in sanitizers_tuples]                     
                    # Build the flow entry
                    flows = [[flow_type, sanitizers_list]]
                    
                    # Create vulnerability name with counter
                    numbered_vuln = f"{vuln_name}_{vulnerability_counters[vuln_name]}"
                    
                    output.append({
                        "vulnerability": numbered_vuln,
                        "source": [source_tuple[0], source_tuple[1]],
                        "sink": [vulnerability.sink[0], vulnerability.sink[1]],
                        "flows": flows
                    })
                    
                    # Increment counter for this vulnerability type
                    vulnerability_counters[vuln_name] += 1
        
        return output

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
