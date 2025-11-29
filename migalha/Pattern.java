import java.util.*;

// defines the structure of a vulnerability: what counts as a source, sanitizer, and sink
public class Pattern {
    private String name;
    private Set<String> sources;
    private Set<String> sanitizers;
    private Set<String> sinks;

    public Pattern(String name, List<String> sources, List<String> sanitizers, List<String> sinks) {
        this.name = name;
        this.sources = new HashSet<>(sources);
        this.sanitizers = new HashSet<>(sanitizers);
        this.sinks = new HashSet<>(sinks);
    }

    public String getName() {
        return name;
    }

    public Set<String> getSources() {
        return new HashSet<>(sources);
    }

    public Set<String> getSanitizers() {
        return new HashSet<>(sanitizers);
    }

    public Set<String> getSinks() {
        return new HashSet<>(sinks);
    }

    public boolean isSource(String s) {
        return sources.contains(s);
    }

    public boolean isSanitizer(String s) {
        return sanitizers.contains(s);
    }

    public boolean isSink(String s) {
        return sinks.contains(s);
    }
}
