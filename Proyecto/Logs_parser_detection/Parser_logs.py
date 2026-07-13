import re
import os
import json
import argparse
import logging

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s: %(message)s'
)

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
    events_list = []
    try:
        log_file_path = os.path.join("logs", "logs_recolectados.log")
        if not os.path.exists(log_file_path):
            logging.error(f"Log file {log_file_path} does not exist.")
            return []
        
        with open(log_file_path, 'r') as log_file:
            content = log_file.read()
            
            events_list = []
            for line in content.split('\n'):
                ips = re.findall(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', line)
                dates = re.findall(r'\d{2}/[A-Za-z]{3}/\d{4}', line)
                times = re.findall(r'\d{2}:\d{2}:\d{2}', line)
                match = re.search(r'"(GET|POST|PUT|DELETE|HEAD|OPTIONS)\s+([^ ]+)\s+HTTP"', line)
                status_codes = re.findall(r'\s(\d{3})\s', line)
                user_agents = re.findall(r'\"[^\"]*\"$', line)
                
                if match:
                    methods = match.group(1)
                    requests = match.group(2)
                else:
                    methods = None
                    requests = None
                        
                data = {
                    "ips": ips[0] if ips else None,
                    "dates": dates[0] if dates else None,
                    "times": times[0] if times else None,
                    "methods": methods,
                    "status_codes": status_codes[0] if status_codes else None,
                    "user_agents": user_agents[0] if user_agents else None,
                    "request": requests
                    }
                    
                events_list.append(data)
        return events_list
    except Exception as e:
        logging.error(f"Error occurred while extracting data from log file: {e}")
        return []
    
def SQL_Injection_Detection(events_list):
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
        value = str(events_list) if isinstance(events_list, list) else events_list

        for name, pattern in type_SQL_injection.items():
            if re.search(pattern, value, re.IGNORECASE):
                logging.warning(f"Type of SQL injection detected: {name}")
                return name
        return None
    except Exception as e:
        logging.error(f"Error occurred while detecting SQL injection: {e}")
        return None

def Path_Transversal_Detection(events_list):
    """
    Check for potential path traversal patterns in the extracted data.
    """
    try:
        event = str(events_list) if events_list else ""
        path_traversal_patterns = [
            r"(\.\./|\.\.\\)",
            r"(%2e%2e/|%2e%2e\\)",
            r"(\.\./\.\./|\.\.\\\.\.\\)",
            r"(%2e%2e/%2e%2e/|%2e%2e\\%2e%2e\\)"
        ]
        
        for pattern in path_traversal_patterns:
            if re.search(pattern, event, re.IGNORECASE):
                return True
        return False
    except Exception as e:
        logging.error(f"Error occurred while detecting path traversal: {e}")
        return False    

def Scan_Detection(events_list):
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
        value = str(events_list)
        
        for pattern in scan_patterns:
            if re.search(pattern, value, re.IGNORECASE):
                logging.warning(f"Potential scan detected in: {pattern}")
                return True
        return False
    except Exception as e:
        logging.error(f"Error occurred while detecting scan: {e}")
        return False

def Risk_assessment(events_list):
    """
    Assess the risk level based on the detected patterns in the extracted data.
    """
    risk_level = "Low"
    
    try:
        for key, value in events_list.items():
            value_str = str(value) if value else ""
            if SQL_Injection_Detection(value_str):
                risk_level = "High"
                break
            if Path_Transversal_Detection(value_str):
                    risk_level = "Medium"
            if Scan_Detection(value_str):
                    risk_level = "Medium"
    except Exception as e:
        logging.error(f"Error occurred while assessing risk: {e}")
    
    logging.info(f"Risk assessment completed. Risk level: {risk_level}")
    return risk_level

def Events_Group_Analysis(events_list):
    """
    Group and analyze events based on the ip addresses.
    """
    try:
        events_by_ip = {}
        for event in events_list:
            ip = event["ips"] if event["ips"] else "unknown"
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

def Report_Generator_General(events_list):
    """General report group by IP"""
    try:
        events_by_ip = Events_Group_Analysis(events_list)
        report_item = []
        
        for ip, events in events_by_ip.items():
            occurrences = len(events)
            
            methods = set(e.get("methods") for e in events if e.get("methods"))
            sql_inj = any (e.get("sql_injection") for e in events)
            path_trav = any (e.get("path_transversal") for e in events)
            scan = any (e.get("scan_detection") for e in events)
            
            risk = "High" if sql_inj else ("Medium" if (path_trav or scan) else "Low")
            
            if occurrences >=50:
                occurrence_status = "Critical"
            elif occurrences>=20:
                occurrence_status = "High"
            elif occurrences >= 10: 
                occurrence_status = "Medium"
            else:
                occurrence_status = "Low"
            
            report_item.append({
                "ip": ip,
                "occurrences": occurrences,
                "recurrence_level": occurrence_status,
                "methods_detected": sorted(list(methods)),
                "sql_injection": sql_inj,
                "path_transversal": path_trav,
                "scan_detected": scan,
                "risk_level": risk
            })
        
        report_item.sort(key = lambda X: X["occurrences"], reverse = True)
        
        report = {"total_ip": len(events_by_ip), "summary": report_item}
        with open(os.path.join(OUTPUT_DIR, "General_Report.json"), "w") as f:
            json.dump(report, f, indent=4)
        
        logging.info("General report generated")
    
    except Exception as e:
        logging.error(f"Error: {e}")
        
def main():
    try: 
        events_list = Data_Extraction()
        
        for event in events_list:
            keys_to_check = list(event.keys())
            request = event.get("request", "")
            user_agent = event.get("user_agents", "")
            
            if SQL_Injection_Detection(request):
                event["sql_injection"] = True
            if Path_Transversal_Detection(request):
                event["path_transversal"] = True
            if Scan_Detection(user_agent):
                event["scan_detection"] = True
            risk_level = Risk_assessment(event)
            event["risk_level"] = risk_level
                    
        events_by_ip = Events_Group_Analysis(events_list)
        Report_Generator(events_list, risk_level)
        Report_Generator_General(events_list)
    except Exception as e:
        logging.error(f"error in main execution: {e}")
        
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Log Parser and Risk Analysis Tool")
    parser.add_argument("--collect", action="store_true", help="Collect logs from the source")
    parser.add_argument("--analyze", action="store_true", help="Analyze the collected logs")
    args = parser.parse_args()

    if args.collect:
        Collector_execution()
    
    if args.analyze:
        main()