import ast
from astexport.export import export_dict
import json

# Maximum number of iterations for while loops to avoid infinite traces
MAX_WHILE_REPETITIONS = 2

def python_to_ast_json(code: str) -> str:
    """
    Parses Python code into an AST and exports it as a JSON string
    """
    tree = ast.parse(code)
    ast_dict = export_dict(tree)
    return json.dumps(ast_dict, indent=4)

def traverse_ast(node: ast.AST, indent=0):
    """
    Recursively traverses an AST, printing each node type and its starting line number.
    """
    prefix = "  " * indent
    node_type = type(node).__name__
    lineno = getattr(node, "lineno", None)

    print(f"{prefix}{node_type} (line {lineno})")

    for child in ast.iter_child_nodes(node):
        traverse_ast(child, indent + 1)

def traces(node: ast.AST):
    """
    Returns all possible execution traces of an AST node.
    Each trace is represented as a list of node descriptions.
    """
    if isinstance(node, ast.Module):
        return combine_sequence(node.body)

    elif isinstance(node, ast.Assign):
        return [[f"Assign(line={node.lineno})"]]

    elif isinstance(node, ast.Expr):
        return [[f"Expr(line={node.lineno})"]]

    elif isinstance(node, ast.If):
        then_traces = combine_sequence(node.body)
        else_traces = combine_sequence(node.orelse)

        result = []
        for t in then_traces:
            result.append([f"If-then(line={node.lineno})"] + t)
        for t in else_traces:
            result.append([f"If-else(line={node.lineno})"] + t)
        return result

    elif isinstance(node, ast.While):
        result = []
        body_traces = combine_sequence(node.body)
        for i in range(MAX_WHILE_REPETITIONS + 1):
            for bt in body_traces:
                result.append([f"While(line={node.lineno}, iter={i})"] + bt * i)
        return result

    else:
        return [[f"{node.__class__.__name__}(line={getattr(node,'lineno',None)})"]]

def combine_sequence(stmts):
    """
    Computes traces for a sequence of AST statements.
    Returns a list of traces, each trace is a list of node descriptions.
    """
    if not stmts:
        return [[]]

    head, *tail = stmts
    head_traces = traces(head)
    tail_traces = combine_sequence(tail)

    result = []
    for h in head_traces:
        for t in tail_traces:
            result.append(h + t)

    return result
