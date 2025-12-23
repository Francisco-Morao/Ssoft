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
        if result.returncode == 0:
            return True, "✅ Output matches expected!"
        else:
            return False, f"❌ Validation failed:\n{result.stdout}\n{result.stderr}"
            
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
    
    # Options
    print("⚙️  Options:")
    validate_patterns_flag = input("   Validate patterns files? (y/N): ").strip().lower() == 'y'
    ignore_lines = input("   Ignore line numbers in validation? (y/N): ").strip().lower() == 'y'
    ignore_implicit = input("   Ignore implicit flows in validation? (y/N): ").strip().lower() == 'y'
    ignore_sanitizers = input("   Ignore sanitizers in validation? (y/N): ").strip().lower() == 'y'
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
        
        # Validate patterns if requested
        if validate_patterns_flag:
            print("🔍 Validating patterns file...")
            success, msg = validate_patterns(patterns_path)
            print(f"   {msg}")
            if success:
                stats['patterns_valid'] += 1
            else:
                stats['patterns_invalid'] += 1
            print()
        
        # Run the analyzer
        print("🔄 Running analyzer...")
        success, error = run_analyzer(slice_path, patterns_path)
        
        if not success:
            print(f"   ❌ Analysis failed: {error}")
            stats['analyzed_failed'] += 1
            print()
            continue
        
        print("   ✅ Analysis completed")
        stats['analyzed_success'] += 1
        
        # Check if output was generated
        generated_output_path = output_dir / f"{test_name}.output.json"
        
        if not generated_output_path.exists():
            print(f"   ⚠️  No output file generated at {generated_output_path}")
            stats['validation_skipped'] += 1
            print()
            continue
        
        print(f"   📝 Output saved to: {generated_output_path}")
        
        # Validate against expected output if it exists
        if expected_output_path:
            print(f"🔍 Validating against expected output...")
            print(f"   Expected: {expected_output_path}")
            
            success, msg = validate_output(
                str(generated_output_path),
                expected_output_path,
                ignore_lines=ignore_lines,
                ignore_implicit=ignore_implicit,
                ignore_sanitizers=ignore_sanitizers
            )
            
            if success is None:
                print(f"   ⏭️  {msg}")
                stats['validation_skipped'] += 1
            elif success:
                print(f"   {msg}")
                stats['validation_success'] += 1
            else:
                print(f"   {msg}")
                stats['validation_failed'] += 1
        else:
            print("   ℹ️  No expected output file to validate against")
            stats['validation_skipped'] += 1
        
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
    print(f"  ❌ Failed:           {stats['validation_failed']}")
    print(f"  ⏭️  Skipped:          {stats['validation_skipped']}")
    print("=" * 70)
    
    # Success rate
    if stats['analyzed_success'] > 0:
        success_rate = (stats['validation_success'] / stats['analyzed_success']) * 100
        print(f"\n🎯 Validation Success Rate: {success_rate:.1f}%")

if __name__ == "__main__":
    main()