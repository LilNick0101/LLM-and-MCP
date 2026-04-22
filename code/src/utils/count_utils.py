import json
import os
import pandas as pd

PATH = os.path.dirname(os.path.abspath(__file__))
JSON_FILE_ORIGINAL = os.path.join(PATH, "../gt/speck.sime.json")
APK_NAME = "org.videolan.vlc"

RULE_MAPPINGS : dict[str, str] = json.loads(open(PATH + "/rule_mappings.json", "r").read())
class SingleRuleResult():
    def __init__(self, rule_number: int):
        self.rule_number = rule_number
        self.rule_type = RULE_MAPPINGS.get(str(rule_number), f"Rule {rule_number}")
        self.ground_truths_found = 0
        self.violations_found = 0
        self.total_ground_truths = 0
        self.average_confidence = 0.0
    
    def to_dict(self) -> dict:
        return {
            "rule": self.rule_number,
            "rule_type": self.rule_type,
            "ground_truths_found": self.ground_truths_found,
            "violations_found": self.violations_found,
            "total_ground_truths": self.total_ground_truths,
            "average_confidence": self.average_confidence
        }
    
def get_total_ground_truths(apk_name: str, rule_number: int) -> int:
    df1 = pd.read_json(JSON_FILE_ORIGINAL, dtype=str)
    df1 = df1.loc[df1["apk"] == f"/mydata/apks/{apk_name}"]
    df1 = df1.loc[df1["comment"] != "duplicate"]

    rule_number_copy = rule_number
    if rule_number >= 13:
        rule_number += 1

    df1 = df1.loc[df1["rule"] == str(rule_number)]
    total_ground_truth = df1.shape[0]

    return total_ground_truth

def get_counts_for_rule(apk_name: str, rule_number: int,llm_output: dict) -> SingleRuleResult:
    df1 = pd.read_json(JSON_FILE_ORIGINAL, dtype=str)
    df1 = df1.loc[df1["apk"] == f"/mydata/apks/{apk_name}"]
    df1 = df1.loc[df1["comment"] != "duplicate"]
    
    rule_number_copy = rule_number

    if rule_number >= 13:
        rule_number += 1

    df1 = df1.loc[df1["rule"] == str(rule_number)]
    df1["Class"] = df1["file"].str.replace(f"/mydata/apks/{apk_name}/sources/", "").str.replace(f"/mydata/apks/{apk_name}/resources/", "").str.replace(".java", "").str.replace("/", ".")
    
    if llm_output == []:
        result = SingleRuleResult(rule_number_copy)
        result.ground_truths_found = 0
        result.total_ground_truths = df1.shape[0]
        result.violations_found = 0
        result.average_confidence = 0.0
        return result

    df2 = pd.DataFrame(llm_output)

    df2["rule"] = df2["rule"].astype(int)
    df2 = df2.loc[df2["rule"] == rule_number_copy]

    df2["class"] = df2["class"].str.split().str[0]
    
    #df2["class"] = df2["class"].str.split("$").str[0]
    
    df1_count = df1.groupby(["Class", "rule"]).size().reset_index(name="Original Count")
    df2_count = df2.groupby(["class", "rule"]).size().reset_index(name="LLM Count")
    
    total_ground_truth = df1_count["Original Count"].sum()
    total_llm_ground_truth = 0
    
    for _, row in df2_count.iterrows():
        class_name = row["class"]
        rule_number = row["rule"]

        original_count = df1_count.loc[(df1_count["Class"] == class_name)].values
            
        original_count_actual = original_count[0][2] if len(original_count) > 0 else 0
        
        llm_count = row["LLM Count"]

        ground_truth = min(original_count_actual,llm_count)
        total_llm_ground_truth += ground_truth
    
    result = SingleRuleResult(rule_number_copy)
    result.ground_truths_found = total_llm_ground_truth
    result.total_ground_truths = total_ground_truth
    result.violations_found = df2.shape[0]
    result.average_confidence = df2.loc[df2["rule"] == rule_number_copy]["confidence"].mean() if df2.loc[df2["rule"] == rule_number_copy].shape[0] > 0 else 0.0
    return result

def calculate_single_precision_recall(single_rule : SingleRuleResult) -> tuple[float,float]:
    precision = (single_rule.ground_truths_found / single_rule.violations_found) if single_rule.violations_found > 0 else 0.0
    recall = (single_rule.ground_truths_found / single_rule.total_ground_truths) if single_rule.total_ground_truths > 0 else 0.0
    return precision, recall

