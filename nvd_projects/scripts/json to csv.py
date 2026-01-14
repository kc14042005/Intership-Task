import json
import csv
import os

def generate_attack_csv(json_file, output_file='attack_patterns.csv'):
    if not os.path.exists(json_file):
        print(f"Error: File not found at {json_file}")
        return

    with open(json_file, 'r', encoding='utf-8') as f:
        data = json.load(f)

    # Define the strict header required by the MERN backend 
    header = ['attack_id', 'name', 'description', 'primary_logs', 'mitre_techniques', 'default_severity']
    
    rows = []
    
    for item in data.get('vulnerabilities', []):
        cve = item.get('cve', {})
        cve_id = cve.get('id', 'UNKNOWN')
        
        # 1. Attack ID (Using CVE ID)
        attack_id = f"AP-{cve_id}"

        # 2. Name & Description
        # We clean the text to avoid CSV breaking on commas or newlines
        desc_raw = cve.get('descriptions', [{}])[0].get('value', 'No description')
        description = desc_raw.replace('\n', ' ').replace('"', "'")[:200] + "..." # Truncate for CSV
        name = f"{cve_id} Exploitation"

        # 3. Severity (0-100 Scale)
        metrics = cve.get('metrics', {})
        cvss_v3 = metrics.get('cvssMetricV31', [])
        if cvss_v3:
            base_score = cvss_v3[0]['cvssData']['baseScore']
            default_severity = int(base_score * 10)
        else:
            default_severity = 50 # Default Medium

        # 4. Primary Logs & MITRE (Logic to map NVD data to your SOC keys)
        # In a real scenario, you might map 'Network' vector to 'firewall'
        primary_logs = "web_logs;system_logs" 
        
        # Attempt to find CWE ID
        weaknesses = cve.get('weaknesses', [])
        mitre_techniques = weaknesses[0]['description'][0]['value'] if weaknesses else "TBD"

        rows.append([attack_id, name, description, primary_logs, mitre_techniques, default_severity])

    # Write to CSV
    try:
        with open(output_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(header) # Write strict header first
            writer.writerows(rows)
        print(f"Successfully created {output_file} with {len(rows)} rows.")
    except Exception as e:
        print(f"Error saving CSV: {e}")

# --- EXECUTION ---
generate_attack_csv(r'F:\nvd_projects\nvd_json\nvdcve-2.0-modified.json\nvdcve-2.0-modified.json')
