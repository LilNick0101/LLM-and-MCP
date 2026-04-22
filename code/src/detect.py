import json
import time
import os
import dotenv
import asyncio
import argparse
import jinja2
from pydantic import BaseModel
from pydantic_ai import Agent, capture_run_messages
from pydantic_ai.mcp import load_mcp_servers
from commons import configure_logfire, get_model, get_package_name, get_parameters_and_settings, get_single_rule
from utils.count_utils import calculate_single_precision_recall, get_counts_for_rule, APK_NAME
from utils.file_utils import append_results_to_file, ensure_directory_exists, append_runs_to_file
from utils.llm_utils import report_error
from utils.openai_cost_calculator import calculate_cost

RULE_SETS = {
    "manifest": [2, 3, 4, 10, 14],
    "manifest2": [19, 20, 22, 26, 27],
    "api": [5, 6, 8, 9, 11],
    "api2":  [12, 13, 16, 18],
    "api3": [23, 28, 29, 30, 31],
    "taint_analysis": [1, 7, 15, 17],
    "taint_analysis2": [21, 24, 25],
    "test": [31],
    "all": list(range(1, 32))
}

chosen_set = "test"

class RuleViolation(BaseModel):
    rule: int
    severity: str
    file: str
    method_or_service: str
    line_of_code: int
    kind: str
    description: str
    confidence: float

    def to_dict(self):
        return {
            "rule": self.rule,
            "severity": self.severity,
            "file": self.file,
            "method_or_service": self.method_or_service,
            "line_of_code": self.line_of_code,
            "kind": self.kind,
            "description": self.description,
            "confidence": self.confidence
        }

dotenv.load_dotenv()

parser = argparse.ArgumentParser(description="Run the Pydantic MCP client.")
parser.add_argument("--remote", "-oai",'-gpt', action="store_true", help="Use an OpenAI model")
parser.add_argument("--gemini", "-g", action="store_true", help="Use a Google Model")
parser.add_argument("--claude", "-c", action="store_true", help="Use an Anthropic model")
parser.add_argument("--runs", "-rn", type=int, help="How many runs to be done (default is 4)",default=5)
parser.add_argument("--rule", "-r", type=int, help="The rule number to test")

args = parser.parse_args()

runs = args.runs

configure_logfire()

PATH = os.path.dirname(os.path.abspath(__file__))
speck_guidelines = open(PATH + "../guidelines/SPECK_guidelines.md", "r").read()


def get_rule_list(rule_set):
    RULES = RULE_SETS[rule_set]
    speck_rule = ""
    for RULE in RULES:
        speck_rule += get_single_rule(RULE)
    return speck_rule

speck_rule = get_rule_list(chosen_set)

env = jinja2.Environment(loader=jinja2.FileSystemLoader(PATH))
prompt_file = open(PATH + "/prompts/detect/prompt.md", "r").read()

async def main():
    try:
        servers = load_mcp_servers(PATH + "../server_configs.json")
        agent = None

        parameters, settings = get_parameters_and_settings()

        model = get_model(args)

        if args.remote == True or args.claude == True:
            agent = Agent(model, toolsets=servers,model_settings=settings, end_strategy="early",retries=5)
        else:
            agent = Agent(model, toolsets=servers, model_settings={"temperature": parameters["temperature"]}, end_strategy="early")


        manifest  = await servers[0].direct_call_tool("get_android_manifest", {})
        package_name = get_package_name(manifest)
        if package_name == "":
            print("Could not find package name in the manifest, fall back to default.")
            package_name = "com.example.vulnerableapp"
        
        print(f"Running with {agent.model.model_name}")
        print(f"Number of runs: {runs}")

        print(f"Package name: {package_name}")

        with capture_run_messages() as messages:
            try:
                async with agent:
                    if args.rule is not None:
                        prompt = env.from_string(prompt_file).render(rules=get_single_rule(args.rule))
                        for i in range(runs):
                            result, execution_time = await run_agent(agent, prompt)

                            save_results(parameters, result, execution_time,package_name)

                            llm_output = [x.to_dict() for x in result.output]
                            save_rule_evaluation(result, execution_time, llm_output, args.rule, package_name)
                    else:
                        for rule in RULE_SETS[chosen_set]:

                            for i in range(runs):
                                print(f"Running rule: {rule} - {i+1}")
                                prompt = env.from_string(prompt_file).render(rules=get_single_rule(rule))

                                result, execution_time = await run_agent(agent, prompt)
                                
                                save_results(parameters, result, execution_time,package_name)
                                
                                llm_output = [x.to_dict() for x in result.output]
                                save_rule_evaluation(result, execution_time, llm_output, rule,package_name)
            except Exception as e:
                print(f"Error occurred while running the agent: {e}.")
                report_error(package_name=package_name,messages=messages,e=e)

    except Exception as e:
        print(f"Error running the agent: {e}")
        return

def print_run_results(result, execution_time : float):
    print(result.output)
    print(f"\nExecution time: {execution_time} seconds ({execution_time:.2f} seconds)")
    print(f"Tokens used: Input {result.usage().input_tokens} Output {result.usage().output_tokens}\n")

def save_rule_evaluation(result, execution_time, llm_output, rule,package_name=APK_NAME):
    if args.gpt == True:
        cost = calculate_cost(model_name="gpt-5", input_tokens=result.usage().input_tokens, output_tokens=result.usage().output_tokens)['total_cost']
    else:        
        cost = 0.0 # TODO: implement cost calculation for other models

    res = get_counts_for_rule(package_name, rule, llm_output)

    prec, rec = calculate_single_precision_recall(res)

    append_runs_to_file(PATH + f"/detect-outputs/runs/runs_{package_name}.json",llm_output)

    append_results_to_file(PATH + f"/detect-outputs/final_results/{package_name}.json",res.to_dict(),execution_time,result.usage().input_tokens,result.usage().output_tokens,cost,prec,rec)

async def run_agent(agent : Agent, prompt: str):
    init_time = time.time()
    result = await agent.run(prompt,output_type=list[RuleViolation])
    final_time = time.time()

    execution_time = final_time - init_time

    print_run_results(result, execution_time)
    return result,execution_time

def save_results(parameters, result, execution_time,package_name=""):
    date = time.strftime("%Y_%m_%d-%H:%M:%S")
    
    output_dicts = [x.to_dict() for x in result.output]
    ensure_directory_exists(f"{PATH}/violations")
    try:
        with open(f"{PATH}/violations/{package_name}.json", "w") as f:
            f.write(json.dumps(output_dicts, indent=4))
        ensure_directory_exists(f"{PATH}/detect-dumps/{package_name}")
        with open(f"{PATH}/detect-dumps/{package_name}/dump-{date}.json", "wb") as f:
            json_data = json.loads(result.all_messages_json())
            f.write(json.dumps(json_data, indent=4).encode())
    except Exception as e:
        print(f"Failed writing result data: {e}")

if __name__ == "__main__":
    
    print("""?
     ____.  _____  ________  ____  ___    _____  ___________________  _________ .__  .__               __   
    |    | /  _  \ \______ \ \   \/  /   /     \ \_   ___ \______   \ \_   ___ \|  | |__| ____   _____/  |_ 
    |    |/  /_\  \ |    |  \ \     /   /  \ /  \/    \  \/|     ___/ /    \  \/|  | |  |/ __ \ /    \   __\\
/\__|    /    |    \|    `   \/     \  /    Y    \     \___|    |     \     \___|  |_|  \  ___/|   |  \  |  
\________\____|__  /_______  /___/\  \ \____|__  /\______  /____|      \______  /____/__|\___  >___|  /__|  
                 \/        \/      \_/         \/        \/                   \/             \/     \/      
/\/\/\/<<! VULN DETECTION AGENT !>>\/\/\/\\ """)
    
    asyncio.run(main())