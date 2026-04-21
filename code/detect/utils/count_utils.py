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
    
    for index, row in df2_count.iterrows():
        class_name = row["class"]
        rule_number = row["rule"]

        original_count = 0

        if class_name.split(".")[0] == "kotlin":
            alternative_class_name = class_name.replace("kotlin", "o",1)
            original_count = df1_count.loc[(df1_count["Class"] == class_name) | (df1_count["Class"] == alternative_class_name)].values
        else:
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

def filter_ground_truths_by_rule(df: list[dict], rule_number: int, apk_name: str) -> list[dict]:
    if df == []:
        return []
    df1 = pd.DataFrame(df)
    df1["rule"] = df1["rule"].astype(int)
    df1 = df1.loc[df1["rule"] == rule_number]

    df1["class"] = df1["class"].str.split().str[0].astype(str)
    
    df2 = pd.read_json(JSON_FILE_ORIGINAL, dtype=str)
    
    df2 = df2.loc[df2["apk"] == f"/mydata/apks/{apk_name}"]
    
    df2 = df2.loc[df2["comment"] != "duplicate"]
    
    if rule_number >= 13:
        rule_number += 1
    df2 = df2.loc[df2["rule"] == str(rule_number)]
    df_copy = df1.copy()
    df2["Class"] = df2["file"].str.replace(f"/mydata/apks/{apk_name}/sources/", "").str.replace(f"/mydata/apks/{apk_name}/resources/", "").str.replace(".java", "").str.replace("/", ".")
    indexes_to_drop = []
    for index, row in df_copy.iterrows():
        class_name = row["class"]
        rule_n = row["rule"]
        df2_loc = None
        if class_name.split(".")[0] == "kotlin":
            alternative_class_name = class_name.replace("kotlin", "o",1)
            df2_loc = df2.loc[(df2["Class"] == class_name) | (df2["Class"] == alternative_class_name)]
        else:
            df2_loc = df2.loc[(df2["Class"] == class_name)]

        if df2_loc.shape[0] == 0:
            indexes_to_drop.append(index)
            continue
    
    df1.drop(indexes_to_drop, inplace=True)
    df1.drop_duplicates(subset=["rule", "severity", "class", "method_or_service"], inplace=True)
    
    return df1.to_dict(orient="records")
