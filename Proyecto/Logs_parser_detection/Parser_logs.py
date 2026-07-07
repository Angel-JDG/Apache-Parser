import re
import os
import json
import argparse
import logging

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_DIR = os.path.join(BASE_DIR, "output")

# expected files from Logs collector
expected_files = ["logs_recolectados.log"]

def files_verifier():
    """
    Verify if the expected files exist in the output directory.
    """
    missing_files = []
    for file in expected_files:
        if not os.path.exists(os.path.join("logs", file)):
            missing_files.append(file)
    
    if missing_files:
        logging.error(f"Missing expected files: {', '.join(missing_files)}")
        return False
    return True

def Collector_execution():
    """
    Execute the log collection process and verify the output files.
    """
    try:
        from Logs_collector import logs_collector
        logs_collector()
        
        if files_verifier():
            logging.info("All expected files are present.")
        else:
            logging.error("Some expected files are missing.")
    except Exception as e:
        logging.error(f"Error occurred while executing log collection: {e}")

def ip_extractor(log_file):
    """
    Extract IP addresses from the given log file.
    """
    ip_pattern = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
    unique_ips = set()

    try:
        with open(log_file, 'r') as f:
            for line in f:
                ips = ip_pattern.findall(line)
                unique_ips.update(ips)
    except FileNotFoundError:
        logging.error(f"Log file {log_file} not found.")
    except Exception as e:
        logging.error(f"Error while extracting IPs: {e}")

    return ips, unique_ips

def ports_extractor(log_file):
    """
    Extract ports from the given log file.
    """
    port_pattern = re.compile(r'\b(?:[0-9]{1,5})\b')
    unique_ports = set()

    try:
        with open(log_file, 'r') as f:
            for line in f:
                ports = port_pattern.findall(line)
                unique_ports.update(ports)
    except FileNotFoundError:
        logging.error(f"Log file {log_file} not found.")
    except Exception as e:
        logging.error(f"Error while extracting ports: {e}")

    return ports, unique_ports

def risk_analysis(log_file):
    """
    Perform risk analysis based on the extracted IPs and ports.
    """
    ips, unique_ips = ip_extractor(log_file)
    ports, unique_ports = ports_extractor(log_file)

    # Placeholder for actual risk analysis logic
    risk_score = len(unique_ips) + len(unique_ports)  # Example metric

    return {
        "unique_ips": list(unique_ips),
        "unique_ports": list(unique_ports),
        "risk_score": risk_score
    }
    
def report_generator(analysis_results):
    """
    Generate a report based on the analysis results.
    """
    report_file = os.path.join(OUTPUT_DIR, "risk_analysis_report.json")
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    try:
        with open(report_file, 'w') as f:
            json.dump(analysis_results, f, indent=4)
        logging.info(f"Report generated at {report_file}")
    except Exception as e:
        logging.error(f"Error while generating report: {e}")
