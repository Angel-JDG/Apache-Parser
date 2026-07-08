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

# collector file script execution
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

# detection of ips from the collected logs of apache2 access.log
def Data_Extraction():
    """
    Extract IPs, dates, times, methods, status codes and user-agents from the collected log files.
    """
    try:
        log_file_path = os.path.join("logs", "logs_recolectados.log")
        if not os.path.exists(log_file_path):
            logging.error(f"Log file {log_file_path} does not exist.")
            return
        
        ips = re.search(r'(\d{1,3}\.){3}\d{1,3}', open(log_file_path).read())
        dates = re.search(r'\d{2}/[A-Za-z]{3}/', open(log_file_path).read())
        times = re.search(r'\d{2}:\d{2}:\d{2}', open(log_file_path).read())
        methods = re.search(r'\"(GET|POST|PUT|DELETE|HEAD|OPTIONS)\"', open(log_file_path).read())
        status_codes = re.search(r'\s(\d{3})\s', open(log_file_path).read())
        user_agents = re.search(r'\"[^\"]*\"$', open(log_file_path).read())
        
        data = {
            "ips": ips.group() if ips else None,
            "dates": dates.group() if dates else None,
            "times": times.group() if times else None,
            "methods": methods.group() if methods else None,
            "status_codes": status_codes.group() if status_codes else None,
            "user_agents": user_agents.group() if user_agents else None
        }
        
        return data
    except Exception as e:
        logging.error(f"Error occurred while extracting data from log file: {e}")
        return {}
    
def SQL_Injection_Detection(data):
    """
    check for potential SQL injection patterns in the extracted data.
    """
    try:
        type_SQL_injection = {
            "SQL meta-characters": r"(\%27)|(\')|(\-\-)|(\%23)|(#)",
            "SQL injection patterns": r"((\%3D)|(=))[^\n]*((\%27)|(\')|(\-\-)|(\%3B)|(;))",
            "SQL injection logical patterns": r"\w*((\%27)|(\'))(\s)*((\%6F)|o|(\%4F))((\%72)|r|(\%52))",
            "UNION-based SQL injection": r"((\%27)|(\'))union",
            "EXEC-based SQL injection": r"exec(\s|\+)+(s|x)p\w+"
        }            
        for key, value in data.items():
            if value:
                for name, pattern in type_SQL_injection.items():
                    if re.search(pattern, value, re.IGNORECASE):
                        logging.warning(f"Type of SQL injection detected: {name}")
                        return name
        return None
    except Exception as e:
        logging.error(f"Error occurred while detecting SQL injection: {e}")
        return None

def Path_Transversal_Detection(data):
    """
    Check for potential path traversal patterns in the extracted data.
    """
    try:
        path_traversal_patterns = [
            r"(\.\./|\.\.\\)",
            r"(%2e%2e/|%2e%2e\\)",
            r"(\.\./\.\./|\.\.\\\.\.\\)",
            r"(%2e%2e/%2e%2e/|%2e%2e\\%2e%2e\\)"
        ]
        
        for key, value in data.items():
            if value:
                for pattern in path_traversal_patterns:
                    if re.search(pattern, value, re.IGNORECASE):
                        logging.warning(f"Potential path traversal detected in {key}: {value}")
                        return True
    except Exception as e:
        logging.error(f"Error occurred while detecting path traversal: {e}")
        return False    

def Scan_Detection(data):
    """
    Check for potential scan patterns in the extracted data.
    """
    try:
        scan_patterns = [
            r"nmap",
            r"nikto",
            r"sqlmap",
            r"dirb",
            r"dirbuster",
            r"fimap",
            r"wpscan"
        ]
    
        for key, value in data.items():
            if value:
                for pattern in scan_patterns:
                    if re.search(pattern, value, re.IGNORECASE):
                        logging.warning(f"Potential scan detected in {key}: {value}")
                        return True
    except Exception as e:
        logging.error(f"Error occurred while detecting scan: {e}")
        return False

def Risk_assessment(data):
    """
    Assess the risk level based on the detected patterns in the extracted data.
    """
    risk_level = "Low"
    
    try:
        if SQL_Injection_Detection(data):
            risk_level = "High"
        elif Path_Transversal_Detection(data):
            risk_level = "Medium"
        elif Scan_Detection(data):
            risk_level = "Medium"
    except Exception as e:
        logging.error(f"Error occurred while assessing risk: {e}")
    
    logging.info(f"Risk assessment completed. Risk level: {risk_level}")
    return risk_level

def Events_Group_Analysis(events):
    """
    Group and analyze events based on the ip addresses.
    """
    try:
        events_by_ip = {}
        for event in events:
            ip = event["ips"]
            if ip:
                if ip not in events_by_ip:
                    events_by_ip[ip] = []
                events_by_ip[ip].append(event)
        return events_by_ip
    except Exception as e:
        logging.error(f"Error occurred while grouping events by IP: {e}")
        return {}

def Report_Generator(data, risk_level):
    """
    Generate a report based on the ip addresses and risk assessment.
    """
    try:
        report = {
            "risk_level": risk_level,
            "events": Events_Group_Analysis(data)
        }
        
        report_file_path = os.path.join(OUTPUT_DIR, "report.json")
        os.makedirs(OUTPUT_DIR, exist_ok=True)
        
        with open(report_file_path, "w") as report_file:
            json.dump(report, report_file, indent=4)
        
        logging.info(f"Report generated at {report_file_path}")
    except Exception as e:
        logging.error(f"Error occurred while generating report: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Log Parser and Risk Analysis Tool")
    parser.add_argument("--collect", action="store_true", help="Collect logs from the source")
    parser.add_argument("--analyze", action="store_true", help="Analyze the collected logs")
    args = parser.parse_args()

    if args.collect:
        Collector_execution()
    
    if args.analyze:
        log_file = os.path.join("logs", "logs_recolectados.log")
        analysis_results = Data_Extraction()
        risk_level = Risk_assessment(analysis_results)
        Report_Generator(analysis_results, risk_level)