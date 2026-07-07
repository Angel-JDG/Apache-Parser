import os
import shutil

log_origen = "/var/log/apache2/access.log"

log_destino = "logs/logs_recolectados.log"

def recolectar_logs():
    if not os.path.exists(log_origen):
        print("El archivo de logs no existe")
        return

    os.makedirs("logs", exist_ok=True)

    shutil.copy(log_origen, log_destino)

    print("Logs recolectados correctamente")


recolectar_logs()