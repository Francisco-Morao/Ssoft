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

# 1. Write a program that takes a program written in Python, extracts its AST, and outputs the result in
# the JSON format. In Python you can import the ast module, and use astexport.export.export_dict
# from astexport, which takes a Python AST and returns its representation in JSON. You can visualize
# the result as a tree using this online tool: http://jsonviewer.stack.hu/.

# 2. Write a function that traverses an AST, and prints, for each node, its node type(field “ast_type”)
# and the line number of where it starts. Make sure you have a recursive function.

# 3. Write a function that traverses an AST, and prints its sets of complete traces, i.e., a representation
# of all possible execution paths. To tackle the cases where the number of possible paths is infinite
# (think of the while loop), you can assume a constant maximum number of repetitions that the loop
# can do. For time reasons, choose only a subset of the possible node types, such as the ones that
# capture the WHILE language constructs. Proceed by case analysis on the node type.

from ast import AST, parse
import ast
from typing import Any, Dict, List, Union
import json
from astexport.export import export_dict


# Exercise 1: Function to convert AST to JSON-like dictionary
def ast_to_dict(py_str: str) -> str:
    """Convert Python source code to its AST representation in dictionary format."""
    ast_py = parse(py_str)
    ast_dict = export_dict(ast_py)
    return json.dumps(ast_dict, indent=4)
    

