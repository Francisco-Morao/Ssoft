import os
import subprocess
import json
from pathlib import Path
import shutil

def find_test_slices(base_dir="slices"):
    """
    Finds all test slices by looking for .py and .patterns.json file pairs.
    Returns a list of tuples: (slice_path, patterns_path, expected_output_path, test_name)
    """
    slices = []
    base_path = Path(base_dir)
    
    if not base_path.exists():
        print(f"❌ Directory '{base_dir}' not found!")
        return slices
    
    # Walk through all subdirectories
    for root, dirs, files in os.walk(base_path):
        root_path = Path(root)
        
        # Find all .py files
        py_files = [f for f in files if f.endswith('.py')]
        
        for py_file in py_files:
            # Check if corresponding .patterns.json exists
            base_name = py_file[:-3]  # Remove .py extension
            patterns_file = f"{base_name}.patterns.json"
            expected_output_file = f"{base_name}.output.json"
            
            patterns_path = root_path / patterns_file
            expected_output_path = root_path / expected_output_file
            
            if patterns_path.exists():
                slice_path = root_path / py_file
                
                slices.append((
                    str(slice_path),
                    str(patterns_path),
                    str(expected_output_path) if expected_output_path.exists() else None,
                    base_name
                ))
    
    return slices

def run_analyzer(slice_path, patterns_path):
    """
    Runs py_analyser.py on a slice.
    Returns (success, error_message)
    Note: py_analyser.py should save output to output/ directory
    """
    try:
        # Run the analyzer
        result = subprocess.run(
            ["python", "py_analyser.py", slice_path, patterns_path],
            capture_output=True,
            text=True,
            timeout=30  # 30 second timeout
        )
        
        # Check if there was an error
        if result.returncode != 0:
            return False, f"Return code {result.returncode}: {result.stderr}"
        
        return True, None
            
    except subprocess.TimeoutExpired:
        return False, "Timeout (30s exceeded)"
    except Exception as e:
        return False, str(e)

def validate_output(generated_output_path, expected_output_path, ignore_lines=False, ignore_implicit=False, ignore_sanitizers=False):
    """
    Runs validate.py to compare generated output with expected output.
    Returns (success, message)
    """
    if not expected_output_path or not os.path.exists(expected_output_path):
        return None, "No expected output file to compare"
    
    if not os.path.exists(generated_output_path):
        return False, "Generated output file not found"
    
    try:
        cmd = [
            "python", "validate.py",
            "-o", generated_output_path,
            "-t", expected_output_path
        ]
        
        # Add optional flags
        if ignore_lines:
            cmd.append("--ignore_lines")
        if ignore_implicit:
            cmd.append("--ignore_implicit")
        if ignore_sanitizers:
            cmd.append("--ignore_sanitizers")
        
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=10
        )
        
        # Check result
        # Return full output for logging (strip ANSI color codes)
        import re
        full_output = result.stdout
        if result.stderr:
            full_output += "\n" + result.stderr
        
        # Remove ANSI color codes
        ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
        full_output = ansi_escape.sub('', full_output)
        
        if result.returncode == 0:
            return True, full_output
        else:
            return False, full_output
            
    except subprocess.TimeoutExpired:
        return False, "Validation timeout"
    except Exception as e:
        return False, f"Validation error: {str(e)}"

def validate_patterns(patterns_path):
    """
    Validates the patterns file using validate.py -p
    Returns (success, message)
    """
    try:
        result = subprocess.run(
            ["python", "validate.py", "-p", patterns_path],
            capture_output=True,
            text=True,
            timeout=10
        )
        
        if result.returncode == 0:
            return True, "✅ Patterns file valid"
        else:
            return False, f"❌ Invalid patterns: {result.stderr}"
            
    except Exception as e:
        return False, f"Validation error: {str(e)}"

def main():
    print("=" * 70)
    print("🚀 Automatic Output Generator & Validator")
    print("   Software Security Project 2025/26")
    print("=" * 70)
    print()
    
    # Configuration
    output_dir = Path("output")
    output_dir.mkdir(exist_ok=True)
    
    # Create validation results file
    validation_log_path = output_dir / "validation_results.md"
    validation_log = open(validation_log_path, "w", encoding="utf-8")
        # Write markdown header
    validation_log.write("# 🚀 Validation Results\n")
    validation_log.write("## Software Security Project 2025/26\n\n")
    validation_log.write("---\n\n")
        # Options
    print("⚙️  Options:")
    validate_patterns_flag = True
    ignore_lines = False
    ignore_implicit = False
    ignore_sanitizers = False
    verbose = False
    print()
    
    # Find all test slices
    print("📁 Scanning for test slices...")
    slices = find_test_slices()
    
    if not slices:
        print("❌ No test slices found!")
        return
    
    print(f"✅ Found {len(slices)} test slice(s)\n")
    
    # Statistics
    stats = {
        'total': len(slices),
        'analyzed_success': 0,
        'analyzed_failed': 0,
        'validation_success': 0,
        'validation_failed': 0,
        'validation_skipped': 0,
        'patterns_valid': 0,
        'patterns_invalid': 0
    }
    
    # Process each slice
    for i, (slice_path, patterns_path, expected_output_path, test_name) in enumerate(slices, 1):
        print("=" * 70)
        print(f"[{i}/{len(slices)}] {test_name}")
        print("=" * 70)
        print(f"📄 Slice:    {slice_path}")
        print(f"📋 Patterns: {patterns_path}")
        
        # Write to log
        validation_log.write(f"\n## [{i}/{len(slices)}] {test_name}\n\n")
        validation_log.write(f"- **Slice:** `{slice_path}`\n")
        validation_log.write(f"- **Patterns:** `{patterns_path}`\n")
        
        # Validate patterns if requested
        if validate_patterns_flag:
            print("🔍 Validating patterns file...")
            success, msg = validate_patterns(patterns_path)
            print(f"   {msg}")
            if success:
                validation_log.write(f"\n- **Pattern Validation:** ✅ Valid\n")
            else:
                validation_log.write(f"\n- **Pattern Validation:** ❌ {msg}\n")
            if success:
                stats['patterns_valid'] += 1
            else:
                stats['patterns_invalid'] += 1
            print()
        
        # Run the analyzer
        analysis_success, error = run_analyzer(slice_path, patterns_path)
        
        if not analysis_success:
            if verbose: #dont show error if not verbose
                print(f"   ❌ Analysis failed: {error}")
                validation_log.write(f"- **Analysis:** ❌ FAILED - `{error}`\n")
            else:
                print(f"   ❌ Analysis failed")
                validation_log.write(f"- **Analysis:** ❌ FAILED\n")
            stats['analyzed_failed'] += 1
            print()
            continue
        
        print("   ✅ Analysis completed")
        validation_log.write("SUCCESS\n")
        stats['analyzed_success'] += 1
        
        # Check if output was generated
        generated_output_path = output_dir / f"{test_name}.output.json"
        if not generated_output_path.exists():
            validation_log.write(f"- **Output:** ⚠️ NOT GENERATED\n")
            stats['validation_skipped'] += 1
            print()
            continue
        
        print(f"   📝 Output saved to: {generated_output_path}")
        validation_log.write(f"- **Output:** `{generated_output_path}`\n")
        
        
        # Validate against expected output if it exists
        if expected_output_path:
            validation_log.write(f"- **Expected:** `{expected_output_path}`\n")
            
            success, msg = validate_output(
                str(generated_output_path),
                expected_output_path,
                ignore_lines=ignore_lines,
                ignore_implicit=ignore_implicit,
                ignore_sanitizers=ignore_sanitizers
            )
            
            if success is None:
                print(f"   ⏭️  {msg}")
                validation_log.write(f"\n### ⏭️ Validation: SKIPPED\n{msg}\n")
                stats['validation_skipped'] += 1
            elif success:
                print(f"   ✅ Output matches expected!")
                validation_log.write(f"\n### ✅ Validation: PASSED\n\n")
                validation_log.write(f"```\n{msg}\n```\n")
                stats['validation_success'] += 1
            else:
                print(f"   {msg}")
                validation_log.write(f"Validation: FAILED\n{msg}\n")
                stats['validation_failed'] += 1
        else:
            print("   ℹ️  No expected output file to validate against")
            validation_log.write(f"\n### ⏭️ Validation: SKIPPED\nNo expected output file to validate against\n")
            stats['validation_skipped'] += 1
        
        validation_log.write("\n---\n")
        print()
    
    # Print summary
    print("=" * 70)
    print("📊 SUMMARY")
    print("=" * 70)
    print(f"Total tests:           {stats['total']}")
    print()
    print("Analysis:")
    print(f"  ✅ Successful:       {stats['analyzed_success']}")
    print(f"  ❌ Failed:           {stats['analyzed_failed']}")
    print()
    
    if validate_patterns_flag:
        print("Pattern Validation:")
        print(f"  ✅ Valid:            {stats['patterns_valid']}")
        print(f"  ❌ Invalid:          {stats['patterns_invalid']}")
        print()
    
    print("Output Validation:")
    print(f"  ✅ Passed:           {stats['validation_success']}")
    
    # Write summary to log
    validation_log.write("\n## 📊 SUMMARY\n\n")
    validation_log.write(f"**Total tests:** {stats['total']}\n\n")
    
    validation_log.write("### Analysis\n\n")
    validation_log.write("| Status | Count |\n")
    validation_log.write("|--------|-------|\n")
    validation_log.write(f"| ✅ Successful | {stats['analyzed_success']} |\n")
    validation_log.write(f"| ❌ Failed | {stats['analyzed_failed']} |\n\n")
    
    if validate_patterns_flag:
        validation_log.write("### Pattern Validation\n\n")
        validation_log.write("| Status | Count |\n")
        validation_log.write("|--------|-------|\n")
        validation_log.write(f"| ✅ Valid | {stats['patterns_valid']} |\n")
        validation_log.write(f"| ❌ Invalid | {stats['patterns_invalid']} |\n\n")
    
    validation_log.write("### Output Validation\n\n")
    validation_log.write("| Status | Count |\n")
    validation_log.write("|--------|-------|\n")
    validation_log.write(f"| ✅ Passed | {stats['validation_success']} |\n")
    validation_log.write(f"| ❌ Failed | {stats['validation_failed']} |\n")
    validation_log.write(f"| ⏭️ Skipped | {stats['validation_skipped']} |\n\n")
    
    if stats['analyzed_success'] > 0:
        success_rate = (stats['validation_success'] / stats['analyzed_success']) * 100
        validation_log.write(f"### 🎯 Validation Success Rate: {success_rate:.1f}%\n")
    
    # Close log file
    validation_log.close()
    print(f"\n📝 Validation results saved to: {validation_log_path}")
    print(f"  ❌ Failed:           {stats['validation_failed']}")
    print(f"  ⏭️  Skipped:          {stats['validation_skipped']}")
    print("=" * 70)
    
    # Success rate
    if stats['analyzed_success'] > 0:
        success_rate = (stats['validation_success'] / stats['analyzed_success']) * 100
        print(f"\n🎯 Validation Success Rate: {success_rate:.1f}%")

if __name__ == "__main__":
    main()