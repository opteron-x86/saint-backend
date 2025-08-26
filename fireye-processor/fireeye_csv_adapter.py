import re
import json
from tqdm import tqdm
from concurrent.futures import ProcessPoolExecutor, as_completed
from dimensional.modules.adapters.base_adapter import BaseDataAdapter

def static_process_fireeye_rule(record, context):
  
    def _get_dates(ref_list):
        # matches 1990 through 2030 dates for YYYYMMDD
        date_pattern = r'(199\d|20[0-2]\d|2030)(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])'
        for ref in ref_list:
            match = re.search(date_pattern, ref, re.IGNORECASE)
            if match:
                # Join the matched groups to form the full date string (YYYYMMDD)
                return ''.join(match.groups())
        return '2024-01-01'  # Return 2024-01-01 if no date is found
 
    rule_name = record.get("Rule Name", "")
    cve_refs = record.get("CVE ID", "").split(",") if record.get("CVE ID") else []
    detected_date = _get_dates(cve_refs)

    entry = context["create_common_structure"]()
    entry.update({
        "title": rule_name,
        "checksum": '',
        "human_hash": '',
        "source_id": record.get("SID"),
        "information_controls": {
            "tlp": context["tlp"],
            "usg": context["get_usg_classification"](rule_name),
            "propin": context["propin"],
            "deploy_auth": "IAP SHARKSEER FireEye"
        },
        "description": rule_name,
        "platform": context["platform"],
        "platform_aor": context["platform_aor"],
        "source_org": context["source_org"],
        "date_published": context["format_date"](detected_date),
        "date_last_modified": context["format_date"](detected_date),
        "date_deployed": context["format_date"](record.get("date_deployed") or detected_date),
        "action": context["action"],
        "cve": context["get_cves"](cve_refs),
        "cwe": context["get_cwes"](cve_refs),
        "malware_family": context["get_malware_family"](rule_name),
        "malware_classification": context["get_malware_classification"](rule_name),
        "mitre_att_tactic": context["get_mitre_att_tactics"](cve_refs),
        "mitre_att_technique": context["get_mitre_att_techniques"](cve_refs),
        "mitre_att_subtechnique": context["get_mitre_att_subtechniques"](cve_refs),
        "references": cve_refs,
        "implementation": record
    })
    return entry

class FireEyeCSVAdapter(BaseDataAdapter):
    def __init__(
            self, 
            debug_mode: bool,
            malclass_crosswalk: str,
            malplat_crosswalk: str,
            overrides: dict[str, str],
            purpose: str,
            sigtype: str, 
            source: str,
            **kwargs
            ):

        if debug_mode:
            for key, value in kwargs.items():
                print(f"Unhandled kwargs: {key} -> {type(value).__name__}: {value}")

        # Extract the specific kwargs before calling super()
        self.debug_mode = bool(debug_mode)
        self.malclass_crosswalk_file = str(malclass_crosswalk)
        self.malplat_crosswalk_file = str(malplat_crosswalk)
        self.overrides = dict(overrides)
        self.purpose = str(purpose)
        self.sigtype = str(sigtype)
        self.source = str(source)
        self.action = str(self.overrides.get('action', ''))
        self.platform = str(self.overrides.get('platform', ''))
        self.platform_aor = str(self.overrides.get('platform_aor', ''))
        self.propin = str(self.overrides.get('propin', ''))
        self.source_org = str(self.overrides.get('source_org', ''))
        self.tlp = str(self.overrides.get('tlp', ''))
        self.usg = str(self.overrides.get('usg', ''))

        super().__init__(**kwargs)

        # Load platform crosswalk from JSON files
        self.malclass_crosswalk = self._load_malclass_crosswalk_file()
        self.malplat_crosswalk = self._load_malplat_crosswalk_file()

        if not sigtype == 'fireeye':
            raise ValueError("Invalid sigtype detected.")

    def _load_malclass_crosswalk_file(self):
        try:
            with open(self.malclass_crosswalk_file, 'r') as file:
                return json.load(file)
        except FileNotFoundError:
            print("Malware mappings JSON file not found.")
            return {}
        except json.JSONDecodeError:
            print("Error decoding the malware mappings JSON file.")
            return {}
    
    def _load_malplat_crosswalk_file(self):
        try:
            with open(self.malplat_crosswalk_file, 'r') as file:
                return json.load(file)
        except FileNotFoundError:
            print("Malware mappings JSON file not found.")
            return {}
        except json.JSONDecodeError:
            print("Error decoding the malware mappings JSON file.")
            return {}

    def process_data(self, data):
        if isinstance(data, str):
            data = json.loads(data)
    
        if isinstance(data, dict):
            records = [item for key in data if isinstance(data[key], list) for item in data[key]]
        else:
            records = data
    
        context = {
            "platform": self.platform,
            "platform_aor": self.platform_aor,
            "source_org": self.source_org,
            "usg": self.usg,
            "propin": self.propin,
            "action": self.action,
            "tlp": self.tlp,
            "get_cves": self._get_cves,
            "get_cwes": self._get_cwes,
            "get_mitre_att_tactics": self._get_mitre_att_tactics,
            "get_mitre_att_techniques": self._get_mitre_att_techniques,
            "get_mitre_att_subtechniques": self._get_mitre_att_subtechniques,
            "get_malware_classification": self._get_malware_classification,
            "get_malware_family": self._get_malware_family,
            "create_common_structure": self.create_common_structure,
            "format_date": self._format_date,
            "get_usg_classification": self._get_usg_classification
        }

        results = []
        with ProcessPoolExecutor() as executor:
            futures = {
                executor.submit(static_process_fireeye_rule, record, context): record
                for record in records
            }
            for future in tqdm(as_completed(futures), total=len(futures), desc="Processing FireEye NX", unit=" rules"):
                try:
                    result = future.result()
                    if result:
                        results.append(result)
                except Exception as e:
                    print(f"❌ Failed processing record: {e}")
                if result:
                    results.append(result)
    
        return results

    def _get_usg_classification(self, rule_name):
        # List of patterns to match
        usg_classification_patterns = [
            r'UNCLASSIFIED//FOR OFFICAL USE ONLY',
            r'UNCLASSIFIED//FOUO',
            r'U//FOR OFFICAL USE ONLY',
            r'U//FOUO',
            r'UNCLASSIFIED//CUI',
            r'U//CUI'
        ]
        # Iterate over each pattern and check for a match
        for pattern in usg_classification_patterns:
            match = re.search(pattern, rule_name, re.IGNORECASE)
            if match:
                classification = match.group(0)
                return classification
        # If no match is found, return a default value
        return self.usg

    def _get_cves(self, cve_list):
        cve_pattern = r'cve-\d{4}-\d{4,7}'
        cves = set()
 
        for value in cve_list:
            found_cves = re.findall(cve_pattern, value, re.IGNORECASE)
            cves.update(cve.upper() for cve in found_cves)
        return sorted(list(cves))
 
    def _get_cwes(self, cwe_list):
        cwe_pattern = r'cwe-\d{2,6}'
        cwes = set()
 
        for value in cwe_list:
            found_cwes = re.findall(cwe_pattern, value, re.IGNORECASE)
            cwes.update(cwe.upper() for cwe in found_cwes)
        return sorted(list(cwes))

    def _get_mitre_att_tactics(self, tactic_list):
        tactic_pattern = r'TA\d{4}'
        tactics = set()
 
        for value in tactic_list:
            found_tactics = re.findall(tactic_pattern, value, re.IGNORECASE)
            tactics.update([tactic.upper() for tactic in found_tactics])
        return sorted(list(tactics))
 
    def _get_mitre_att_techniques(self, technique_list):
        technique_pattern = r'(?<!\w)(?:T0\d{3}|T1\d{3})(?![._\d])'
        techniques = set()
 
        for value in technique_list:
            found_techniques = re.findall(technique_pattern, value, re.IGNORECASE)
            techniques.update([technique.upper() for technique in found_techniques])
        return sorted(list(techniques))
 
    def _get_mitre_att_subtechniques(self, subtechnique_list):
        # subtechnique_pattern matches T1234.001 and T1234_001
        subtechnique_pattern = r'(?<!\w)(?:T0\d{3}|T1\d{3})[._]\d{3}'
        subtechniques = set()
    
        for value in subtechnique_list:
            found_subtechniques = re.findall(subtechnique_pattern, value, re.IGNORECASE)
            # Replace underscore with a dot
            modified_subtechniques = [subtechnique.replace('_', '.') for subtechnique in found_subtechniques]
            subtechniques.update([subtechnique.upper() for subtechnique in modified_subtechniques])
        return sorted(list(subtechniques))

    def _get_malware_classification(self, rule_name):
        matched_classifications = []
        rule_name = rule_name.strip().lower()
        # Check if category directly matches a malware classification
        for classification, aliases in self.malclass_crosswalk.items():
            # Check for malware family name match in the rule_name
            if re.search(rf'\b{re.escape(classification.lower())}\b', rule_name):
                matched_classifications.append(classification)
            # Check for alias matches in the rule_name
            if any(re.search(rf'\b{re.escape(alias.lower())}\b', rule_name) for alias in aliases):
                matched_classifications.append(classification)
        # Remove duplicates by converting to a set and back to a list, if needed
        return sorted(list(set(matched_classifications)))
    
    def _get_malware_family(self, malware_names):
        matched_malware_families = []
        malware_names = malware_names.lower()
        # Iterate over malware families and their aliases
        for malware, data in self.malplat_crosswalk.items():
            # Check for malware family name match in the sig
            if re.search(rf'\b{re.escape(malware.lower())}\b', malware_names):
                matched_malware_families.append(malware)
            # Check for alias matches in the sig
            if any(re.search(rf'\b{re.escape(alias.lower())}\b', malware_names) for alias in data.get('aliases', [])):
                matched_malware_families.append(malware)
        # Remove duplicates by converting to a set and back to a list, if needed
        return sorted(list(set(matched_malware_families)))