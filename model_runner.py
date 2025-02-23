import subprocess
import sys
import os

def run_phishing_model(link):
    """Executes the phishing detection model and returns the result."""
    python_exe = "python"  # or "python3" depending on your system
    script_file = "test_phishing.py"  # Since it's in the same folder
    
    print(f"Running model with: {link}")  # Print the link for debugging
    print(f"Executing: {python_exe} {script_file} {link}")  # Print the command

    try:
        result = subprocess.run(
            [python_exe, script_file, link],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True,
            timeout=30  # Add timeout to prevent hanging
        )
        
        # Check for errors first
        if result.stderr:
            print(f"Model error: {result.stderr.strip()}")
            return "-1"  # Return -1 to indicate error
            
        # Check if we have valid output
        output = result.stdout.strip()
        if output and output in ["0", "1"]:
            return output
        else:
            print(f"Invalid model output: {output}")
            return "-1"  # Return -1 for invalid output
            
    except subprocess.TimeoutExpired:
        print("Model execution timed out")
        return "-1"
    except Exception as e:
        print(f"Error running model: {str(e)}")
        return "-1"