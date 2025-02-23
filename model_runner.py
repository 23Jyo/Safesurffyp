import subprocess
import sys
import os

def run_phishing_model(link):
    """Executes the phishing detection model using the virtual environment's Python."""
    python_exe = os.path.join(os.getcwd(), "env", "Scripts", "python.exe")  # Get venv Python path
    script_file = "test_phishing.py"  # Ensure the script is in the same folder
    
    print(f"Running model with: {link}")  # Debugging
    print(f"Executing: {python_exe} {script_file} {link}")  # Debugging

    try:
        result = subprocess.run(
            [python_exe, script_file, link],  # Use venv Python
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True,
            timeout=30  # Prevent hanging
        )
        
        # Check for errors
        if result.stderr:
            print(f"Model error: {result.stderr.strip()}")
            return "-1"  # Indicate error
            
        # Validate output
        output = result.stdout.strip()
        if output in ["0", "1"]:
            return output
        else:
            print(f"Invalid model output: {output}")
            return "-1"
            
    except subprocess.TimeoutExpired:
        print("Model execution timed out")
        return "-1"
    except Exception as e:
        print(f"Error running model: {str(e)}")
        return "-1"
