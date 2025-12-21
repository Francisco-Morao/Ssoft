import ast

def print_ast_nodes(node, indent=0):
    """
    Recursively traverse an AST node and print its type and line number.
    """
    node_type = type(node).__name__
    lineno = getattr(node, "lineno", None)  # Not all nodes have 'lineno'
    print("  " * indent + f"{node_type} (line {lineno})")
    
    # Iterate over all fields of the node
    for field_name, value in ast.iter_fields(node):
        if isinstance(value, ast.AST):
            print_ast_nodes(value, indent + 1)
        elif isinstance(value, list):
            for item in value:
                if isinstance(item, ast.AST):
                    print_ast_nodes(item, indent + 1)


def traverse_ast(node: ast.AST, indent=0,):
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
        traverse_ast(child, indent + 1)

# Example usage
if __name__ == "__main__":
    source_code = """
def add(a, b):
    return a + b

x = add(2, 3)
print(x)
"""
    tree = ast.parse(source_code)
    traverse_ast(tree)
        # print_ast_nodes(tree)
