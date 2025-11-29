import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

// combines multiple Labels in order to analyze many vulnerabilities at once, keeping their flows separate and independent
public class MultiLabel {
    private final Map<Pattern, Label> labels;

    public MultiLabel() {
        this.labels = new HashMap<>();
    }

    public MultiLabel(Set<Pattern> patterns) {
        this.labels = new HashMap<>();
        for (Pattern p : patterns) {
            this.labels.put(p, new Label());
        }
    }

    public MultiLabel(MultiLabel other) {
        this.labels = new HashMap<>();
        for (Map.Entry<Pattern, Label> entry : other.labels.entrySet()) {
            this.labels.put(entry.getKey(), new Label(entry.getValue())); 
        }
    }

    public Map<Pattern, Label> getLabels() {
        return Collections.unmodifiableMap(labels);
    }

    public Label getLabel(Pattern p) {
        return labels.get(p);
    }

    public void addSource(String sourceName) {
        for (Pattern p : labels.keySet()) {
            if (p.isSource(sourceName)) {
                labels.get(p).addSource(sourceName);
            }
        }
    }

    public void addSanitizer(String sourceName, String sanitizerName) {
        for (Pattern p : labels.keySet()) {
            if (p.isSanitizer(sanitizerName)) {
                if (p.isSource(sourceName)) {
                    labels.get(p).addSanitizer(sourceName, sanitizerName);
                }
            }
        }
    }

    public MultiLabel combine(MultiLabel other) {
        MultiLabel combined = new MultiLabel(this);

        for (Pattern p : other.labels.keySet()) {
            Label otherLabel = other.labels.get(p);

            combined.labels.putIfAbsent(p, new Label());

            Label merged = combined.labels.get(p).combine(otherLabel);
            combined.labels.put(p, merged);
        }

        return combined;
    }
}
