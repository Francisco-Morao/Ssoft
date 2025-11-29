import java.util.*;

// Stores illegal information flows detected in a program slice, grouped by vulnerability name.
public class Vulnerabilities {

    // key = vulnerability name
    // value = list of detected illegal flows (each flow recorded as text or object)
    private final Map<String, List<IllegalFlow>> vulnerabilities;

    public Vulnerabilities() {
        this.vulnerabilities = new HashMap<>();
    }

    public static class IllegalFlow {
        public final String sinkName;
        public final Map<String, Set<String>> flows; // sources -> sanitizers

        public IllegalFlow(String sinkName, Map<String, Set<String>> flows) {
            this.sinkName = sinkName;
            this.flows = flows;
        }

        @Override
        public String toString() {
            return "Sink=" + sinkName + ", flows=" + flows.toString();
        }
    }

    public void record(MultiLabel illegalML, String sinkName) {
        for (Map.Entry<Pattern, Label> entry : illegalML.getLabels().entrySet()) {
            Pattern p = entry.getKey();
            Label label = entry.getValue();

            vulnerabilities.putIfAbsent(p.getName(), new ArrayList<>());
            vulnerabilities.get(p.getName())
                    .add(new IllegalFlow(sinkName, label.getFlows()));
        }
    }

    public Map<String, List<IllegalFlow>> getAll() {
        return Collections.unmodifiableMap(vulnerabilities);
    }
}
