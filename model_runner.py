import subprocess

def run_phishing_model(link):
    """Executes the phishing detection model and returns the result."""
    python_exe = "C:\\ProgramData\\Anaconda3\\python.exe"  # Update this path if needed
    script_file = "D:\\FYP\\test_phishing.py"  # Path to your model script

    print(f"Running model with: {link}")  # Print the link for debugging
    print(f"Executing: {python_exe} {script_file} {link}")  # Print the command

    try:
        result = subprocess.run(
            [python_exe, script_file, link],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True
        )
        print(f"Model output: {result.stdout.strip()}")  # Print model output
        print(f"Model error (if any): {result.stderr.strip()}")  # Print errors

        return result.stdout.strip() or "No output from model"
    except Exception as e:
        print(f"Error running model: {str(e)}")
        return f"Error running model: {str(e)}"
