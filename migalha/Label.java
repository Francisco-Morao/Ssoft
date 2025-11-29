import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

// tracks how information from sources flows and which sanitizers were applied for one vulnerability pattern
public class Label {
    // key - the name of the source
    // value - name of the sanitizers applied to information of that source
    private final Map<String, Set<String>> flows;

    public Label() {
        this.flows = new HashMap<>();
    }

    public Label(Label other) {
        this.flows = new HashMap<>();
        for (Map.Entry<String, Set<String>> entry : other.flows.entrySet()) {
            this.flows.put(entry.getKey(), new HashSet<>(entry.getValue()));
        }
    }

    public void addSource(String source) {
        flows.putIfAbsent(source, new HashSet<>());
    }

    public void addSanitizer(String source, String sanitizer) {
        flows.putIfAbsent(source, new HashSet<>());
        flows.get(source).add(sanitizer);
    }

    public Map<String, Set<String>> getFlows() {
        Map<String, Set<String>> copy = new HashMap<>();
        for (String src : flows.keySet()) {
            copy.put(src, Collections.unmodifiableSet(flows.get(src)));
        }
        return Collections.unmodifiableMap(copy);
    }

    public Set<String> getSources() {
        return Collections.unmodifiableSet(flows.keySet());
    }

    public Set<String> getSanitizersFor(String source) {
        return flows.containsKey(source)
                ? Collections.unmodifiableSet(flows.get(source))
                : Collections.emptySet();
    }

    public Label combine(Label other) {
        Label combined = new Label(this);

        for (Map.Entry<String, Set<String>> entry : other.flows.entrySet()) {
            String src = entry.getKey();
            Set<String> sanitizers = entry.getValue();

            combined.flows.putIfAbsent(src, new HashSet<>());
            combined.flows.get(src).addAll(sanitizers);
        }

        return combined;
    }
}
