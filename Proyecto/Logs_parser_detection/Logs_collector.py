import os
import shutil

log_origin= "/var/log/apache2/access.log"

log_final = "logs/logs_recolectados.log"

def logs_collector():
    try:
        
        if not os.path.exists(log_origin):
            print(f"logs files directory not found: {log_origin}")
            return
        
        if os.path.getsize(log_origin) == 0:
            print(f"logs files directory is empty: {log_origin}")   
            return False
        
        os.makedirs("logs", exist_ok=True)
        shutil.copy(log_origin, log_final)
        
        if os.path.getsize(log_origin) > 0:
            print(f"logs files directory is collected successfully ({os.path.getsize(log_final)} bytes)")   
            return True
        else:
            print("File copied but is empty")
            return False
    except PermissionError:
        print(f"permission denied reading {log_origin}")
        return False
    except Exception as e:
        print(f"Error while collecting logs: {e}")
        
if __name__ == "__main__":
    logs_collector()