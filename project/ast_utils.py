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

import ast
from astexport.export import export_dict
import json
import traverses_op

def eval_expr(node, policy, multilabelling, vulns):
    # Delegate expression evaluation to traverses_op's dispatcher
    return traverses_op.eval_expr(node, policy, multilabelling, vulns)

# Maximum number of iterations for while loops to avoid infinite traces
MAX_WHILE_REPETITIONS = 2

def python_to_ast_json(code: str) -> str:
    """
    Parses Python code into an AST and exports it as a JSON string
    """
    tree = ast.parse(code)
    ast_dict = export_dict(tree)
    return json.dumps(ast_dict, indent=4)

def python_to_ast(code: str) -> ast.AST:
    """
    Parses Python code into an AST
    """
    tree = ast.parse(code)
    return tree

def traverse_ast(node: ast.AST, indent=0):
    """
    Recursively traverses an AST, printing each node type and its starting line number.

    1. Extend your function that walks ASTs corresponding to expressions, so that it receives, besides
    the expression node, objects of the Policy, MultiLabelling, and Vulnerabilities classes, and returns a
    MultiLabel object that describes the information that is returned by the given expression.
    
    • use the multilabelling to determine the multilabels of the variables that appear in the expression
    • use multilabel operations for creating, updating and combining multilabels
    • note that, as it encounters function calls, which could be sinks to some of the vulnerability
    patterns that are being search for, it should check whether the information that is reaching
    the function via its arguments consist of an illegal information flow. use the policy to find
    what illegal flows are possibly hapening, and save those as detected vulnerabilities
    """

    prefix = " " * indent
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
    
    # TODO CHANGE THIS TO HANDLE MORE NODE TYPES
    
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