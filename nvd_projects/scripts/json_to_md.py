import json
import os

def generate_attack_patterns(json_file, output_file='attack_patterns.md'):
    # Check if file exists before trying to load
    if not os.path.exists(json_file):
        print(f"Error: File not found at {json_file}")
        return

    # Load your NVD data
    with open(json_file, 'r', encoding='utf-8') as f:
        data = json.load(f)

    markdown_content = "# Attack Patterns Catalog\n\n"
    
    # Iterate through each vulnerability in the list
    for item in data.get('vulnerabilities', []):
        cve = item.get('cve', {})
        cve_id = cve.get('id', 'UNKNOWN')
        
        # [cite_start]1. Get Description [cite: 40]
        descriptions = cve.get('descriptions', [])
        desc_text = descriptions[0].get('value', 'No description') if descriptions else 'No description'
        
        # [cite_start]2. Get Severity (Try V3, fall back to V2) [cite: 41]
        metrics = cve.get('metrics', {})
        cvss_v3 = metrics.get('cvssMetricV31', [])
        if cvss_v3:
            score = cvss_v3[0]['cvssData']['baseScore']
            severity = cvss_v3[0]['cvssData']['baseSeverity']
            severity_line = f"{severity} (score {int(score * 10)})"
        else:
            severity_line = "MEDIUM (score 50)" # Default if metric missing

        # [cite_start]3. Get Targets (Products) [cite: 40]
        targets = set()
        for config in cve.get('configurations', []):
            for node in config.get('nodes', []):
                for match in node.get('cpeMatch', []):
                    # Parse "cpe:2.3:a:vendor:product:..."
                    if 'criteria' in match:
                        parts = match['criteria'].split(':')
                        if len(parts) >= 5:
                            targets.add(f"{parts[3]} {parts[4]}")
        target_list = ", ".join(list(targets)[:5]) # List first 5

        # [cite_start]4. Get Weakness ID (CWE) to map to MITRE [cite: 41]
        weaknesses = cve.get('weaknesses', [])
        cwe_id = "TBD"
        if weaknesses:
            desc = weaknesses[0].get('description', [])
            if desc:
                cwe_id = desc[0].get('value', 'TBD')

        # [cite_start]5. Build the Block strictly following the guide's template [cite: 38-42]
        block = f"""## AP-{cve_id} : {cve_id} Exploitation
Description: {desc_text}
Targets: {target_list}
Indicators:
- Traffic matching {cve_id} signatures
- Unexpected behavior on {target_list}
Log Sources Needed:
- web_logs (primary)
- system_logs
MITRE Mapping:
- {cwe_id} (CWE)
Possible Detections:
- DET-{cve_id}
Severity Baseline:
- {severity_line}
False Positive Notes:
- Vulnerability scanners testing for {cve_id}
\n"""
        markdown_content += block

    # Save the file
    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(markdown_content)
        print(f"Successfully created {output_file} using {len(data.get('vulnerabilities', []))} entries.")
    except Exception as e:
        print(f"Error saving file: {e}")

# --- EXECUTION LINE ---
# We use r'' to handle the backslashes in your Windows path correctly
generate_attack_patterns(r'F:\nvd_projects\nvd_json\nvdcve-2.0-modified.json\nvdcve-2.0-modified.json')
