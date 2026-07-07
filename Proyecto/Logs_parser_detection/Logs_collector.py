import os
import shutil

log_origin= "/var/log/apache2/access.log"

log_final = "logs/logs_recolectados.log"

def logs_collector():
    try:
        
        if not os.path.exists(log_origin):
            print("logs files directory not found")
            return
        
        os.makedirs("logs", exist_ok=True)
        shutil.copy(log_origin, log_final)
        print("logs files collected successfully")
        
    except Exception as e:
        print(f"Error while collecting logs: {e}")


logs_collector()