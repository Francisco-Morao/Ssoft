import java.util.*;

// represents a mapping from program variable names to multilabels
public class MultiLabelling {

    private final Map<String, MultiLabel> map;

    public MultiLabelling() {
        this.map = new HashMap<>();
    }

    public MultiLabel get(String name) {
        return map.getOrDefault(name, new MultiLabel());
    }

    public void set(String varName, MultiLabel ml) {
        map.put(varName, new MultiLabel(ml));
    }

    public boolean contains(String name) {
        return map.containsKey(name);
    }

    public Map<String, MultiLabel> getAll() {
        return Collections.unmodifiableMap(map);
    }
}
