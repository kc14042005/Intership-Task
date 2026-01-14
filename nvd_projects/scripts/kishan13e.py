import csv
import yaml
import os
import sys

def load_csv_ids(filepath, id_column):
    """Returns a set of IDs from a CSV column."""
    ids = set()
    if not os.path.exists(filepath):
        print(f"❌ Missing File: {filepath}")
        return ids
    
    with open(filepath, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            if id_column in row:
                ids.add(row[id_column].strip())
    return ids

def load_yaml_ids(filepath, root_key, id_key='id'):
    """Returns a set of IDs from a YAML list."""
    ids = set()
    if not os.path.exists(filepath):
        print(f"❌ Missing File: {filepath}")
        return ids

    with open(filepath, 'r', encoding='utf-8') as f:
        data = yaml.safe_load(f)
        for item in data.get(root_key, []):
            ids.add(item.get(id_key))
    return ids

def validate_integrity():
    print("🔍 Starting Knowledge Base Validation...\n")
    errors = 0

    # 1. LOAD REFERENCE IDs (The "Truth")
    # These are the IDs that MUST exist for others to reference them
    attack_ids = load_csv_ids('knowledge_base/attack_patterns/attack_patterns.csv', 'attack_id')
    severity_ids = load_yaml_ids('knowledge_base/severity/severity_rules.yaml', 'severity_rules')
    
    # Load Detections (Central Hub)
    detection_ids = set()
    detections_data = []
    det_path = 'knowledge_base/detections/detections.yaml'
    
    if os.path.exists(det_path):
        with open(det_path, 'r', encoding='utf-8') as f:
            detections_data = yaml.safe_load(f).get('detections', [])
            for d in detections_data:
                detection_ids.add(d['id'])
    else:
        print(f"❌ Critical: {det_path} is missing!")
        return

    # 2. VALIDATE DETECTIONS.YAML
    print(f"📋 Validating {len(detections_data)} Detections...")
    for det in detections_data:
        d_id = det['id']
        
        # Check Attack ID Link
        if det['attack_id'] not in attack_ids:
            print(f"   🚩 [Error] {d_id} references missing attack_id: {det['attack_id']}")
            errors += 1
            
        # Check Severity Rule Link
        if det['severity_rule'] not in severity_ids:
            print(f"   🚩 [Error] {d_id} references missing severity_rule: {det['severity_rule']}")
            errors += 1

    # 3. VALIDATE MITRE MAPPING
    print("\n📋 Validating MITRE Mapping...")
    mitre_rows = []
    if os.path.exists('knowledge_base/mitre/mitre_mapping.csv'):
        with open('knowledge_base/mitre/mitre_mapping.csv', 'r') as f:
            mitre_rows = list(csv.DictReader(f))
    
    for row in mitre_rows:
        if row['detection_id'] not in detection_ids:
            print(f"   🚩 [Error] MITRE map references unknown detection: {row['detection_id']}")
            errors += 1

    # 4. VALIDATE ML FEATURES
    print("\n📋 Validating ML Requirements...")
    ml_rows = []
    if os.path.exists('knowledge_base/ml_requirements/ml_features.csv'):
        with open('knowledge_base/ml_requirements/ml_features.csv', 'r') as f:
            ml_rows = list(csv.DictReader(f))

    for row in ml_rows:
        req_for = row['required_for']
        # 'required_for' might be a detection ID or severity ID
        if req_for not in detection_ids and req_for not in severity_ids:
            print(f"   🚩 [Error] Feature '{row['feature_name']}' required for unknown ID: {req_for}")
            errors += 1

    # SUMMARY
    print("\n" + "="*30)
    if errors == 0:
        print("✅ SUCCESS: Integrity Check Passed! Artifacts are ready for MERN/DS teams.")
    else:
        print(f"❌ FAILED: Found {errors} integrity errors. Do not merge yet.")

# --- EXECUTION ---
# Ensure you are running this from the 'soc-tool' root folder
validate_integrity()
