import argparse
import json
import os
import ast_utils
import traverses_op

from Pattern import Pattern
from Policy import Policy
from MultiLabelling import MultiLabelling
from Vulnerabilities import Vulnerabilities

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

	ast_tree = ast_utils.python_to_ast(code)

	policy = Policy(patterns)
	current_labelling = MultiLabelling(map={})
	vulnerabilities = Vulnerabilities()

	for stmt in ast_tree.body:
		current_labelling = traverses_op.traverse_stmt(stmt, policy, current_labelling, vulnerabilities)
	 
	output_dir = os.path.join(os.getcwd(), "output")
	os.makedirs(output_dir, exist_ok=True)
 
	base = os.path.splitext(os.path.basename(slice_path))[0]
	out_filename = f"{base}.output.json"
	out_path = os.path.join(output_dir, out_filename)
	output_data = vulnerabilities.as_output("explicit")	# "implicit" or "explicit" TODO CHANGE LATER
	f = open(out_path, "w", encoding="utf-8")
	json.dump(output_data, f, ensure_ascii=False, indent=4)
	f.close() 

if __name__ == "__main__":
	main()

