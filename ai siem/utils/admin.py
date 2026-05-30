import ctypes
import sys
import tkinter.messagebox as messagebox
import tkinter as tk

def is_admin():
    """Check if running with administrator privileges."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except:
        return False

def run_as_admin():
    """Restart script with Administrator privileges."""
    try:
        # Properly quote arguments to handle paths with spaces (e.g., "project seim.py")
        args = " ".join([f'"{arg}"' for arg in sys.argv])
        
        result = ctypes.windll.shell32.ShellExecuteW(
            None,
            "runas",
            sys.executable,
            args,
            None,
            1
        )
        
        # ShellExecute returns > 32 if successful
        if result <= 32:
            return False
        return True
    except Exception as e:
        print(f"Failed to elevate privileges: {e}")
        return False

def check_and_request_admin():
    """
    Check admin status. If not admin, request UAC.
    Returns True if current process is admin or user accepted limited mode.
    Returns False if process should exit (because it successfully launched admin process).
    """
    print("Checking admin...")
    if is_admin():
        print("Running as admin")
        return True
        
    print("Requesting Administrator privileges...")
    success = run_as_admin()
    
    if success:
        # The admin process has been launched successfully, this process should exit
        return False
        
    # If we get here, elevation failed or was denied
    print("Administrator access denied. Running in limited monitoring mode.")
    
    # Show warning to user
    try:
        root = tk.Tk()
        root.withdraw()
        messagebox.showwarning(
            "Administrator Access Denied",
            "SentinelAI could not get Administrator privileges.\n\n"
            "Some features like deep Windows log analysis and USB monitoring "
            "will be restricted. Running in limited monitoring mode."
        )
        root.destroy()
    except:
        pass
        
    return True  # Continue in limited mode
