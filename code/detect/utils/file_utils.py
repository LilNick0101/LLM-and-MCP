import json
import os
import time

def ensure_file_exists(file_path: str):
    if not os.path.exists(file_path):
        with open(file_path, 'w') as file:
            file.write('[]\n')

def ensure_directory_exists(directory_path: str):
    if not os.path.exists(directory_path):
        os.makedirs(directory_path)

def append_runs_to_file(file_path: str, runs: list) -> None:
    try:
        ensure_file_exists(file_path)
        
        json_file = open(file_path, 'r')
        json_data = []
        if os.path.exists(file_path):
            json_file = json_file.read()
            if len(json_file.strip()) > 0:
                json_data = json.loads(json_file)
            else:
                json_data = []
        else:
            json_data = []

        #json_data = json.loads(open(file_path, 'r').read())
        if not isinstance(json_data, list):
            json_data = []
        json_data.extend(runs)
        with open(file_path, 'w') as file:
            content = json.dumps(json_data, indent=4)
            file.write(content + '\n')
    except Exception as e:
        print(f"Error appending runs to file: {e}")
            
def append_results_to_file(file_path: str, results: dict, execution_time: float, input_token_usage: int, output_token_usage: int, cost: float, precision: float, recall: float) -> None:
    try:
        ensure_file_exists(file_path)
        
        json_file = open(file_path, 'r')
        json_data = []
        if os.path.exists(file_path):
            json_file = json_file.read()
            if len(json_file.strip()) > 0:
                json_data = json.loads(json_file)
            else:
                json_data = []
        else:
            json_data = []

        #json_data = json.loads(open(file_path, 'r').read())
        if not isinstance(json_data, list):
            json_data = []
        json_data.append({
                "rule": int(results["rule"]),
                "rule_type": results["rule_type"],
                "violations_found": int(results["violations_found"]),
                "ground_truths_found": int(results["ground_truths_found"]),
                "total_ground_truths": int(results["total_ground_truths"]),
                "precision": round(float(precision*100), 2),
                "recall": round(float(recall*100),2),
                "execution_time": float(execution_time),
                "input_token_usage": int(input_token_usage),
                "output_token_usage": int(output_token_usage),
                "cost": round(float(cost), 2),
                "confidence": round(float(results["average_confidence"]), 2),
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
            })
        with open(file_path, 'w') as file:
            content = json.dumps(json_data, indent=4)
            file.write(content + '\n')
    except Exception as e:
        print(f"Error appending results to file: {e}")


if __name__ == "__main__":
    test_file_path = os.path.join(os.path.dirname(__file__), '..', 'test_results.json')
    ensure_file_exists(test_file_path)
    sample_results = {
        "rule": 6,
        "rule_type": "API Invocation",
        "violations_found": 6,
        "ground_truths_found": 5,
        "total_ground_truths": 12,
        "average_confidence": 0.87
    }
    append_results_to_file(
        test_file_path,
        sample_results,
        execution_time=64.75767970085144,
        input_token_usage=255455,
        output_token_usage=1450,
        precision=0.8333333333333334,
        recall=0.4166666666666667
    )