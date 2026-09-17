import re 
 
def parse_log_line(line: str) -> dict: 
    ip_match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', line) 
    ip_address = ip_match.group(0) if ip_match else "Unknown" 
     
    severity = "LOW" 
    if "Failed password" in line: 
        severity = "MEDIUM" 
    elif "Encrypted" in line or "locked" in line: 
        severity = "HIGH" 
         
    return { 
        "raw_log": line.strip(), 
        "ip_address": ip_address, 
        "severity": severity 
    }
def process_log_file(file_path: str = "data/sample_syslog.log") -> list: 
    results = [] 
    with open(file_path, "r", encoding="utf-8") as f: 
        for line in f: 
            if line.strip(): 
                results.append(parse_log_line(line)) 
    return results