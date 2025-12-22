import argparse
import ast
import json
import os
import ast_utils
from Pattern import Pattern
from Policy import Policy
from typing import Set


def build_handlers(patterns):
	"""Return a mapping of AST node types to actions.

	Adjust the handlers to use `patterns` for vulnerability-specific logic.
	"""

	def on_assign(node: ast.Assign):
		targets = [t.id for t in node.targets if isinstance(t, ast.Name)]
		print(f"Assign to {targets} at line {node.lineno}")

	def on_call(node: ast.Call):
		func_name = None
		if isinstance(node.func, ast.Name):
			func_name = node.func.id
		elif isinstance(node.func, ast.Attribute):
			func_name = node.func.attr
		if func_name:
			print(f"Call to {func_name} at line {node.lineno}")

	return {
		ast.Assign: on_assign,
		ast.Call: on_call,
	}

def main():
	parser = argparse.ArgumentParser()
	parser.add_argument("slice_path")
	parser.add_argument("patterns_path")
	args = parser.parse_args()

	slice_path = args.slice_path
	with open(slice_path, "r", encoding="utf-8") as f:
		code = f.read()
	patterns_path = args.patterns_path

	f =  open(patterns_path, "r", encoding="utf-8")
	patterns_data = json.load(f)
	f.close()

	patterns = [
		Pattern(
			vulnerability_name=p["vulnerability"],
			sources=p.get("sources", []),
			sinks=p.get("sinks", []),
			sanitizers=p.get("sanitizers", []),
		)
		for p in patterns_data
	]
 
	policy = Policy(patterns=list(patterns))

	ast_tree = ast_utils.python_to_ast(code)

	print(policy)
 
	print(ast_utils.traverse_ast(ast_tree, 4, policy))
		
	output_dir = os.path.join(os.getcwd(), "output")
	os.makedirs(output_dir, exist_ok=True)
 
	base = os.path.splitext(os.path.basename(slice_path))[0]
	out_filename = f"{base}.output.json"
	out_path = os.path.join(output_dir, out_filename)
 
	output_data = {
			"vulnerability": "Example Vulnerability",
			"source": [],
			"sink": [],
			"flows": []
		}
	f = open(out_path, "w", encoding="utf-8")
	json.dump(output_data, f, ensure_ascii=False, indent=2)
	f.close() 

if __name__ == "__main__":
	main()

