import argparse
import json
import os
import sys

def main():
	parser = argparse.ArgumentParser()
	parser.add_argument("slice_path")
	parser.add_argument("patterns_path")
	args = parser.parse_args()

	slice_path = args.slice_path
	patterns_path = args.patterns_path

	f = open(patterns_path, "r", encoding="utf-8")
	patterns = json.load(f)

	output_dir = os.path.join(os.getcwd(), "output")
	os.makedirs(output_dir, exist_ok=True)

	

	base = os.path.splitext(os.path.basename(slice_path))[0]
	out_filename = f"{base}.output.json"
	out_path = os.path.join(output_dir, out_filename)
 
	# CALL THE ANALYSER TOOL HERE
	
 
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

