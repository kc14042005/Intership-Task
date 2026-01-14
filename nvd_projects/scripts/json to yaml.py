import json
import os

def generate_detections_yaml(json_file, output_file='detections.yaml'):
    if not os.path.exists(json_file):
        print(f"Error: File not found at {json_file}")
        return

    with open(json_file, 'r', encoding='utf-8') as f:
        data = json.load(f)

    yaml_content = "detections:\n"

    for item in data.get('vulnerabilities', []):
        cve = item.get('cve', {})
        cve_id = cve.get('id', 'UNKNOWN')
        
        # Safe description for YAML (remove newlines/quotes)
        desc = cve.get('descriptions', [{}])[0].get('value', 'No description').replace('\n', ' ').replace('"', "'")[:100] + "..."
        
        # Standard ID Naming
        det_id = f"DET-{cve_id}"
        attack_id = f"AP-{cve_id}"  # MUST match your CSV file

        # The Template Block
        block = f"""  - id: {det_id}
    name: Detection for {cve_id}
    description: "{desc}"
    attack_id: {attack_id}
    log_sources: [web_logs, system_logs]
    rule_type: threshold
    query:
      event: "generic_event"
      condition: "payload contains '{cve_id}'"
    fields_used:
      - src_ip
      - timestamp
    thresholds:
      match_count: 1
    severity_rule: SEV-GENERIC
    labels:
      alert_type: "exploitation"
    response_playbook:
      - "Verify source IP reputation"
      - "Check for successful payload execution"
      - "Isolate affected host if confirmed"
"""
        yaml_content += block

    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(yaml_content)
        print(f"Successfully created {output_file} with skeletons for {len(data.get('vulnerabilities', []))} detections.")
    except Exception as e:
        print(f"Error saving YAML: {e}")

# --- EXECUTION ---
generate_detections_yaml(r'F:\nvd_projects\nvd_json\nvdcve-2.0-modified.json\nvdcve-2.0-modified.json')
