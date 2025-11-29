import ast

MAX_LOOP = 2  # Maximum number of loop iterations to avoid infinite paths

def get_traces(node):
    """
    Recursively get all execution traces from an AST node.
    Each trace is a list of strings representing statements executed in order.
    """
    node_type = type(node).__name__

    if node_type == "Module":
        traces = [[]]  # Start with an empty trace
        for stmt in node.body:
            new_traces = []
            for trace in traces:
                for subtrace in get_traces(stmt):
                    new_traces.append(trace + subtrace)
            traces = new_traces
        return traces

    elif node_type == "Assign":
        target = node.targets[0].id  # assume simple target
        value = ast.dump(node.value)
        return [[f"Assign {target} = {value}"]]

    elif node_type == "Expr":
        value = ast.dump(node.value)
        return [[f"Expr {value}"]]

    elif node_type == "If":
        # Get traces for the "then" branch
        then_traces = [[]]
        for stmt in node.body:
            new_traces = []
            for trace in then_traces:
                for subtrace in get_traces(stmt):
                    new_traces.append(trace + subtrace)
            then_traces = new_traces
        
        # Get traces for the "else" branch
        else_traces = [[]]
        for stmt in node.orelse:
            new_traces = []
            for trace in else_traces:
                for subtrace in get_traces(stmt):
                    new_traces.append(trace + subtrace)
            else_traces = new_traces

        # Execution paths: condition + then or else
        cond = ast.dump(node.test)
        traces = [[f"If {cond}"] + t for t in then_traces] + [[f"If {cond}"] + t for t in else_traces]
        return traces

    elif node_type == "While":
        # Limit loop iterations to MAX_LOOP
        loop_traces = [[]]  # zero iterations
        body_traces = [[]]
        for stmt in node.body:
            new_traces = []
            for trace in body_traces:
                for subtrace in get_traces(stmt):
                    new_traces.append(trace + subtrace)
            body_traces = new_traces

        all_traces = loop_traces.copy()
        for i in range(1, MAX_LOOP + 1):
            for t in body_traces:
                all_traces.append([f"While {ast.dump(node.test)} iteration {i}"] + t)
        return all_traces

    else:
        # Other nodes: just dump them
        return [[f"{node_type}: {ast.dump(node)}"]]

# --- Example usage ---

source_code = """
x = 0
while x < 2:
    x = x + 1
    if x % 2 == 0:
        print(x)
"""

tree = ast.parse(source_code)
traces = get_traces(tree)

for i, t in enumerate(traces):
    print(f"Trace {i+1}:")
    for step in t:
        print("  ", step)
    print("---")
