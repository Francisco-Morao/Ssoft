import ast
import MultiLabel
from astexport.export import export_dict
import json
from Policy import Policy
from MultiLabelling import MultiLabelling
from Vulnerabilities import Vulnerabilities

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

def traverse_ast(node: ast.AST, indent=0, Policy=None, MultiLabelling=None, Vulnerabilities=None):
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


    prefix = "  " * indent
    node_type = type(node).__name__
    lineno = getattr(node, "lineno", None)

    print(f"{prefix}{node_type} (line {lineno})")

    for child in ast.iter_child_nodes(node):
        traverse_ast(child, indent + 1, Policy, MultiLabelling, Vulnerabilities)

    #ast.Call
    #ast.UnaryOp
    #ast.BoolOp

def traverse_Name(node: ast.Name, Policy: Policy, MultiLabelling: MultiLabelling, Vulnerabilities: Vulnerabilities):
    """
    Handles traversal of ast.Name nodes.
    """
    return MultiLabelling.get_label(node.id)
    
def traverse_Constant(node: ast.Constant, Policy: Policy, MultiLabelling: MultiLabelling, Vulnerabilities: Vulnerabilities): 
    """
    Handles traversal of ast.Constant nodes.
    """
    # TODO
    # Constants are considered to have the lowest security label
    return MultiLabel.MultiLabel.lowest_label()

def traverse_BinOp(node: ast.BinOp, Policy: Policy, MultiLabelling: MultiLabelling, Vulnerabilities: Vulnerabilities):
    """
    Handles traversal of ast.BinOp nodes.
    """
    pass
    # TODO

def traverse_Compare(node: ast.Compare, Policy: Policy, MultiLabelling: MultiLabelling, Vulnerabilities: Vulnerabilities):    
    """
    Handles traversal of ast.Compare nodes.
    """
    pass
    # TODO
    # Implement logic for handling ast.Compare nodes
    

def traverse_Attribute(node: ast.Attribute, Policy: Policy, MultiLabelling: MultiLabelling, Vulnerabilities: Vulnerabilities):
    """
    Handles traversal of ast.Attribute nodes.
    """
    pass
    # TODO

    # Implement logic for handling ast.Attribute nodes
    
def traverse_Subscript(node: ast.Subscript, Policy: Policy, MultiLabelling: MultiLabelling, Vulnerabilities: Vulnerabilities):
    """
    Handles traversal of ast.Subscript nodes.
    """
    pass
    # TODO

    # Implement logic for handling ast.Subscript nodes
  
def traverse_Assign(node: ast.Assign, Policy: Policy, MultiLabelling: MultiLabelling, Vulnerabilities: Vulnerabilities):
    """
    Handles traversal of ast.Assign nodes.
    """
    pass
    # TODO

    # Implement logic for handling ast.Assign nodes

def traverse_If(node: ast.If, Policy: Policy, MultiLabelling: MultiLabelling, Vulnerabilities: Vulnerabilities):    
    """
    Handles traversal of ast.If nodes.
    """
    pass
    # TODO

    # Implement logic for handling ast.If nodes

def traverse_While(node: ast.While, Policy: Policy, MultiLabelling: MultiLabelling, Vulnerabilities: Vulnerabilities):
    """
    Handles traversal of ast.While nodes.
    """
    pass
    # TODO

    # Implement logic for handling ast.While nodes

def traverse_Expr(node: ast.Expr, Policy: Policy, MultiLabelling: MultiLabelling, Vulnerabilities: Vulnerabilities):
    """
    Handles traversal of ast.Expr nodes.
    """
    pass
    # TODO

    # Implement logic for handling ast.Expr nodes

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
