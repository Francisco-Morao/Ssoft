# To track them, it will be necessary to determine the security class that captures the information that
# is tested in all ifs and whiles that dominate the assignments, or in other words, that captures the
# information that is associated to the knowledge of what point of the program that is being
# considered (think of the program counter).

# 2. Extend your function that walks ASTs corresponding to expressions, so that it also
# receives a security class corresponding to the program counter, and takes it into consideration when
# detecting illegal flows that arrive to potential sinks.

# 3. statements, when analysing instructions that could establish a flow to a sink, and updates it for recursive calls for
# analysing code whose execution depends on additional conditions

# Extend the class Policy with an operation that, given a name and a multilabel that
# describes the information that is flowing from the program counter, determines the corresponding
# illegal flows, i.e., which part of the multilabel is concerned with implict flows and has the given
# name as a sink. It should return a multilabel that is like the one received as parameter, but that only
# assigns labels to patterns for which an illegal flow is taking place.

import ast
import dataclasses 
from MultiLabel import MultiLabel

@dataclasses.dataclass
class ProgramCounter:

    # Keep track of the security classes of the conditions of all enclosing if and while statements.

    # These security classes represent the security level of the program counter.


    # Push the security label of a condition when entering a region of code controlled by that condition.

    # Pop it when exiting that region.

    stack = []

    def push(self, label: MultiLabel):
        self.stack.append(label)

    def pop(self):
        if self.stack:
            self.stack.pop()

    def current_label(self) -> MultiLabel:
        if self.stack:
            return self.stack[-1]
        else:
            return None
    
    def multi_label(self) -> MultiLabel:
        """ Combine all labels in the stack to form a multilabel representing the current pc level. For the detect_illegal_flows method. 
        #TODO: fact check this method 
        """
        combined_ml = MultiLabel()
        for label in self.stack:
            combined_ml = combined_ml.combinor(label)
        return combined_ml

