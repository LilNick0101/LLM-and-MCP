
import argparse
from enum import Enum
import time
import json
import os

from utils.file_utils import ensure_directory_exists

PARENT_PATH = os.path.dirname(os.path.abspath(__file__ + "/.."))

class ReasoningEffort(str, Enum):
    MINIMAL = "minimal"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"

def get_next_violation(package_name, rule) -> list[dict]:
    violations = []
    vuln_file_path = f"{PARENT_PATH}/violations/{package_name}.json"
    if not os.path.exists(vuln_file_path):
        print("File does not exists")
        return violations
    with open(vuln_file_path, "r") as f:
        all_vulns = json.load(f)
        class_name = ""
        for v in all_vulns:
            if v["rule"] == rule and "automatic_verification" not in v and (class_name == "" or v["class"] == class_name):
                v_copy = dict(v)
                violations.append(v_copy)
                break
    return violations

def mark_violation_as_verified(package_name, violation: dict, verdict: bool, positive: bool, output: str,conversation_file : str = ""):
    vuln_file_path = f"{PARENT_PATH}/violations/{package_name}.json"
    if not os.path.exists(vuln_file_path):
        return
    with open(vuln_file_path, "r") as f:
        all_vulns = json.load(f)
    for v in all_vulns:
        if v["class"] == violation["violation"] and v["lineNumber"] == violation["lineNumber"] and v["rule"] == violation["rule"]:
            v["llm_verdict"] = verdict
            v["automatic_verification"] = positive
            v["verification_output"] = output
            if conversation_file:
                v["conversation_file"] = conversation_file
    with open(vuln_file_path, "w") as f:
        json.dump(all_vulns, f, indent=4)

def report_error(package_name : str,messages : str,e : Exception):

    ensure_directory_exists(f"{PARENT_PATH}/errors/{package_name}")

    date = time.strftime("%Y_%m_%d-%H:%M:%S")

    header = f"""An error occurred while running the agent.
Error message: {str(e)}

Details of the agent state:
"""
    with open(f"{PARENT_PATH}/errors/{package_name}/error-{date}.md", "w") as f:
        f.write(header + "\n" + str(messages))

def parse_args():
    parser = argparse.ArgumentParser(description="Run the JADX MCP client.")
    parser.add_argument("--remote", "-oai",'-gpt', action="store_true", help="Use an OpenAI model")
    parser.add_argument("--gemini", "-g", action="store_true", help="Use a Google Model")
    parser.add_argument("--claude", "-c", action="store_true", help="Use an Anthropic model")
    parser.add_argument("--rule", "-r", type=int, help="The rule number to test")

    args = parser.parse_args()
    return args