### Pattern
Represents a vulnerability pattern describing what counts as an illegal information flow.
A pattern specifies:
- sources: origins of untrusted data
- sanitizers: functions that clean or validate data
- sinks: dangerous operations that should not receive unsanitized data

It provides methods to check whether a given name is a source, sanitizer, or sink and to retrieve these sets.

### Label
Represents the security history of data for a single vulnerability pattern.
It tracks:
- which sources contributed to the data
- which sanitizers were applied to each source

Labels can be combined, merging source and sanitizer information when values flow together.

### MultiLabel
Tracks multiple vulnerability patterns simultaneously.
It maintains a mapping:
Pattern -> Label
This allows the system to independently track taint information for each vulnerability type at the same time.

### Policy
Represents the global information-flow policy derived from all vulnerability patterns.
It supports:
- finding patterns where a given name acts as a source, sanitizer, or sink
- detecting illegal flows by checking which patterns treat a given variable name as a sink and returning only the relevant labels indicating violations

### MultiLabelling
A mapping from program variable names to their respective MultiLabels.
It provides methods to retrieve the multilabel for a variable and update it as the analysis progresses.

### Vulnerabilities
Stores all illegal flows discovered during the analysis.
Each entry records:
- the vulnerability pattern involved
- the sink where the violation occurred
- the sources and sanitizers associated with the flow

This data can later be used to generate a report of all detected vulnerabilities.

### Analysis flow

```
Patterns → Policy
      ↓
Slice of Python Code → Your Parser
      ↓
MultiLabelling  ← tracks taint for each variable
      ↓
MultiLabel  ← tracks taint per vulnerability pattern
      ↓
Label ← tracks taint per source & sanitizers
      ↓
Policy.detectIllegalFlows()
      ↓
Vulnerabilities.record()
      ↓
Final vulnerability report
```