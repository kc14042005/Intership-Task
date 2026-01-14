import yaml

def generate_severity_rules(output_file='knowledge_base/severity/severity_rules.yaml'):
    
    # Define the Standard Rules
    severity_data = {
        "severity_rules": [
            {
                "id": "SEV-GENERIC",
                "name": "Generic Vulnerability Severity",
                "base": 50,
                "modifiers": [
                    {
                        "condition": "event_outcome == 'success'",
                        "add": 30,
                        "desc": "Boost score if exploitation was successful"
                    },
                    {
                        "condition": "dest_is_critical_asset == true",
                        "add": 20,
                        "desc": "Boost score if target is a critical server"
                    }
                ],
                "mapping": {
                    "0-39": "Low",
                    "40-69": "Medium",
                    "70-89": "High",
                    "90-100": "Critical"
                }
            },
            {
                "id": "SEV-CRITICAL-CVE",
                "name": "Critical CVE Exploitation",
                "base": 80,
                "modifiers": [
                    {
                        "condition": "source_ip_reputation == 'malicious'",
                        "add": 15,
                        "desc": "Known attacker IP"
                    }
                ],
                "mapping": {
                    "0-39": "Low",
                    "40-69": "Medium",
                    "70-89": "High",
                    "90-100": "Critical"
                }
            }
        ]
    }

    # Write to YAML
    try:
        # Use a library or manual write to preserve order/format if needed
        # Here we manually write to ensure it matches the guide's look
        with open(output_file, 'w') as f:
            f.write("severity_rules:\n")
            for rule in severity_data['severity_rules']:
                f.write(f"  - id: {rule['id']}\n")
                f.write(f"    name: {rule['name']}\n")
                f.write(f"    base: {rule['base']}\n")
                f.write("    modifiers:\n")
                for mod in rule['modifiers']:
                    f.write(f"      - condition: \"{mod['condition']}\"\n")
                    f.write(f"        add: {mod['add']}\n")
                f.write("    mapping:\n")
                for k, v in rule['mapping'].items():
                    f.write(f"      {k}: {v}\n")
                f.write("\n")
        
        print(f"Successfully created {output_file} with {len(severity_data['severity_rules'])} rules.")
        
    except Exception as e:
        print(f"Error: {e}")

# --- EXECUTION ---
# Ensure the folder exists first
import os
os.makedirs('knowledge_base/severity', exist_ok=True)
generate_severity_rules()
