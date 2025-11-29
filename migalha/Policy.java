import java.util.*;

// represents an information-flow policy built from a set of vulnerability patterns, responsible for determining which flows are illegal.
public class Policy {

    private final Set<Pattern> patterns;

    public Policy(Set<Pattern> patterns) {
        this.patterns = new HashSet<>(patterns);
    }

    public Set<String> getVulnerabilitiesWithSource(String source) {
        Set<String> result = new HashSet<>();
        for (Pattern p : patterns) {
            if (p.isSource(source)) {
                result.add(p.getName());
            }
        }
        return result;
    }

    public Set<String> getVulnerabilitiesWithSanitizer(String sanitizer) {
        Set<String> result = new HashSet<>();
        for (Pattern p : patterns) {
            if (p.isSanitizer(sanitizer)) {
                result.add(p.getName());
            }
        }
        return result;
    }

    public Set<String> getVulnerabilitiesWithSink(String sink) {
        Set<String> result = new HashSet<>();
        for (Pattern p : patterns) {
            if (p.isSink(sink)) {
                result.add(p.getName());
            }
        }
        return result;
    }

    public MultiLabel detectIllegalFlows(String name, MultiLabel multiLabel) {
        MultiLabel illegal = new MultiLabel();

        for (Pattern p : multiLabel.getLabels().keySet()) {
            if (p.isSink(name)) {
                // this pattern considers name to be a sink, meaning illegal flow
                Label copy = new Label(multiLabel.getLabel(p));
                illegal.getLabels().put(p, copy);
            }
        }

        return illegal;
    }
}
