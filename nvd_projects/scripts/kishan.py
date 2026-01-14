import json
import csv
import os

def generate_ml_features(json_file, output_file='ml_features.csv'):
    # Clean path logic (same as before to avoid errors)
    if json_file.endswith(".json\\nvdcve-2.0-modified.json"):
        json_file = json_file.replace(".json\\nvdcve-2.0-modified.json", ".json")
    
    if not os.path.exists(json_file):
        print(f"Error: File not found at {json_file}")
        return

    with open(json_file, 'r', encoding='utf-8') as f:
        data = json.load(f)

    # Required Header [cite: 149]
    header = ['feature_name', 'source_field', 'log_source', 'datatype', 'description', 'required_for', 'example']
    
    rows = []
    
    # Standard features we always want for these types of NVD exploits
    # This dictionary maps a keyword in the description to a feature needed
    feature_map = {
        "sql": {
            "name": "sql_keyword_count",
            "field": "count_matches(payload, ['SELECT', 'UNION', 'DROP'])",
            "source": "web_logs",
            "type": "int",
            "desc": "Count of SQL keywords in payload"
        },
        "buffer overflow": {
            "name": "payload_length",
            "field": "length(payload)",
            "source": "system_logs",
            "type": "int",
            "desc": "Length of the input string"
        },
        "directory traversal": {
            "name": "path_depth_count",
            "field": "count_matches(uri, '../')",
            "source": "web_logs",
            "type": "int",
            "desc": "Count of directory traversal attempts"
        }
    }

    for item in data.get('vulnerabilities', []):
        cve = item.get('cve', {})
        cve_id = cve.get('id', 'UNKNOWN')
        desc = cve.get('descriptions', [{}])[0].get('value', '').lower()
        detection_id = f"DET-{cve_id}"

        # Logic: Scan description to guess the right feature
        # Default feature if nothing specific matches
        feature_data = {
            "name": "request_rate_1m",
            "field": "count(events)",
            "source": "web_logs",
            "type": "int",
            "desc": "Volume of requests in 1 minute"
        }

        # Check for specific keywords
        for key, feat in feature_map.items():
            if key in desc:
                feature_data = feat
                break

        # Append row [cite: 149-152]
        rows.append([
            feature_data['name'],
            feature_data['field'],
            feature_data['source'],
            feature_data['type'],
            feature_data['desc'],
            detection_id,  # linking this feature to the specific CVE detection
            "10" # example value
        ])

    # Save to CSV
    os.makedirs('knowledge_base/ml_requirements', exist_ok=True)
    final_path = os.path.join('knowledge_base/ml_requirements', output_file)

    try:
        with open(final_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(header)
            writer.writerows(rows)
        print(f"SUCCESS: Created {final_path} with {len(rows)} feature requirements.")
    except Exception as e:
        print(f"Error saving CSV: {e}")

# --- EXECUTION ---
path = r'F:\nvd_projects\nvd_json\nvdcve-2.0-modified.json'
generate_ml_features(path)
