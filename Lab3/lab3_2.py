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


# Example usage
if __name__ == "__main__":
    source_code = """
def add(a, b):
    return a + b

x = add(2, 3)
print(x)
"""
    tree = ast.parse(source_code)
    print_ast_nodes(tree)
