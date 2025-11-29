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

	if not os.path.isfile(slice_path):
		sys.exit(1)
	if not os.path.isfile(patterns_path):
		sys.exit(1)

	try:
		with open(patterns_path, "r", encoding="utf-8") as f:
			patterns = json.load(f)
	except Exception:
		sys.exit(1)

	output_dir = os.path.join(os.getcwd(), "output")
	try:
		os.makedirs(output_dir, exist_ok=True)
	except Exception:
		sys.exit(1)

	base = os.path.splitext(os.path.basename(slice_path))[0]
	out_filename = f"{base}.output.json"
	out_path = os.path.join(output_dir, out_filename)

	output_data = {
		"slice": os.path.abspath(slice_path),
		"patterns_file": os.path.abspath(patterns_path),
		"patterns": patterns,
	}

	try:
		with open(out_path, "w", encoding="utf-8") as out_f:
			json.dump(output_data, out_f, ensure_ascii=False, indent=2)
	except Exception:
		sys.exit(1)


if __name__ == "__main__":
	main()

