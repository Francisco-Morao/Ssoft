import ast
import json
from astexport.export import export_dict
import sys

def python_file_to_ast_json(filename):
    # Read source code
    with open(filename, "r", encoding="utf-8") as f:
        source = f.read()

    # Parse Python source into AST
    tree = ast.parse(source, filename=filename)

    # Convert AST to dictionary
    ast_dict = export_dict(tree)

    # Convert dictionary to JSON
    return json.dumps(ast_dict, indent=2)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python ast_to_json.py <python_file.py>")
        sys.exit(1)

    filename = sys.argv[1]
    ast_json = python_file_to_ast_json(filename)
    print(ast_json)
