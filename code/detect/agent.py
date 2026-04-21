import json
import time
import os
import dotenv
import asyncio
import logfire
import argparse
import jinja2
from enum import Enum
from pydantic import BaseModel
from pydantic_ai import Agent, capture_run_messages
from pydantic_ai.mcp import load_mcp_servers
from pydantic_ai.models.openai import OpenAIChatModel, OpenAIResponsesModelSettings
from pydantic_ai.providers.ollama import OllamaProvider
from pydantic_ai.models.google import GoogleModel
from pydantic_ai.providers.google import GoogleProvider
from pydantic_ai.models.anthropic import AnthropicModel
from pydantic_ai.providers.anthropic import AnthropicProvider
from utils.count_utils import calculate_single_precision_recall, get_counts_for_rule, APK_NAME, get_total_ground_truths
from utils.file_utils import append_results_to_file, ensure_directory_exists, append_runs_to_file
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

class ReasoningEffort(str, Enum):
    MINIMAL = "minimal"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"

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
parser.add_argument("--remote", "-oai",'-gpt', action="store_true", help="Use OpenAI MCP client")
parser.add_argument("--gemini", "-g", action="store_true", help="Use Gemini MCP client")
parser.add_argument("--claude", "-c", action="store_true", help="Use Claude MCP client (not implemented yet)")
parser.add_argument("--runs", "-r", help="How many runs to be done (default is 4)",default=5)
parser.add_argument("--rule", "-r", type=int, help="The rule number to test")

args = parser.parse_args()

runs = int(args.runs)

logfire.configure()
logfire.instrument_pydantic_ai()

def scrubbing_callback(m: logfire.ScrubMatch):
    return m.value

logfire.configure(scrubbing=logfire.ScrubbingOptions(callback=scrubbing_callback))

PATH = os.path.dirname(os.path.abspath(__file__))
speck_guidelines = open(PATH + "../guidelines/SPECK_guidelines.md", "r").read()


def get_rule_list(rule_set):
    RULES = RULE_SETS[rule_set]
    speck_rule = ""
    for RULE in RULES:
        speck_rule += get_single_rule(RULE)
    return speck_rule

def get_single_rule(rule_number):
    speck_guidelines_idx = speck_guidelines.find("## A.{} Rule {}".format(rule_number, rule_number))
    speck_guidelines_idx_end = speck_guidelines.find("## A.{} Rule {}".format(rule_number + 1, rule_number + 1))

    if speck_guidelines_idx == -1:
        raise ValueError(f"Rule {rule_number} is not a valid rule.")
    
    if speck_guidelines_idx_end != -1:
        return speck_guidelines[speck_guidelines_idx:speck_guidelines_idx_end] + "\n"
    else:
        return speck_guidelines[speck_guidelines_idx:] + "\n"

speck_rule = get_rule_list(chosen_set)

env = jinja2.Environment(loader=jinja2.FileSystemLoader(PATH))
prompt_file = open(PATH + "/prompt.md", "r").read()

async def main():
    try:
        servers = load_mcp_servers(PATH + "../server_configs.json")
        agent = None

        parameters = {
            "temperature": 0.0,
            "presence_penalty": 0.4,
            "frequency_penalty": 0.3,
            "reasoning_effort": ReasoningEffort.MEDIUM,
            "reasoning_summary": "concise",
            "top_p": 1.0,
        }
        settings = OpenAIResponsesModelSettings(
            temperature=parameters["temperature"],
            openai_reasoning_effort=parameters["reasoning_effort"],
            openai_reasoning_summary=parameters["reasoning_summary"],
            top_p=parameters["top_p"],
        )
        
        if args.remote == True:
            agent = Agent('openai:gpt-5', toolsets=servers,model_settings=settings, end_strategy="early",retries=5)
        elif args.claude == True:
            provider = AnthropicProvider()
            model = AnthropicModel('claude-sonnet-4-6', provider=provider)
            agent = Agent(model, toolsets=servers, model_settings={"temperature": parameters["temperature"]}, end_strategy="early")
        elif args.gemini == True:
            provider = GoogleProvider()
            model = GoogleModel('gemini-3-flash', provider=provider)
            agent = Agent(model, toolsets=servers, model_settings={"temperature": parameters["temperature"]}, end_strategy="early")
        else:
            provider = OllamaProvider(base_url='http://localhost:11435/v1')
            ollama_model = OpenAIChatModel(
                model_name='gpt-oss:120b',
                provider=provider
            )
            agent = Agent(ollama_model, toolsets=servers, model_settings=settings,retries=10)


        manifest  = await servers[0].direct_call_tool("get_android_manifest", {})
        package_name = ""
        for line in manifest["content"]:
            if "package=" in line:
                package_name = line.split('package="')[1].split('"')[0]
                break
        if package_name == "":
            print("Could not find package name in the manifest, fall back to default.")
            package_name = "com.example.app"
        
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

    append_runs_to_file(PATH + f"/runs/runs_{package_name}.json",llm_output)

    append_results_to_file(PATH + f"/final_results/{package_name}.json",res.to_dict(),execution_time,result.usage().input_tokens,result.usage().output_tokens,cost,prec,rec)

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
    ensure_directory_exists(f"{PATH}/outputs/{package_name}")
    try:
        with open(f"{PATH}/outputs/{package_name}/output-{date}.json", "w") as f:
            f.write(json.dumps(output_dicts, indent=4))
        ensure_directory_exists(f"{PATH}/dumps/{package_name}")
        with open(f"{PATH}/dumps/{package_name}/dump-{date}.json", "wb") as f:
            json_data = json.loads(result.all_messages_json())
            f.write(json.dumps(json_data, indent=4).encode())
    except Exception as e:
        print(f"Failed writing result data: {e}")

def report_error(package_name,messages : str,e : Exception):

    ensure_directory_exists(f"{PATH}/errors/{package_name}")

    date = time.strftime("%Y_%m_%d-%H:%M:%S")

    header = f"""An error occurred while running the agent.
Error message: {str(e)}

Details of the agent state:
"""
    with open(f"{PATH}/errors/{package_name}/error-{date}.md", "w") as f:
        f.write(header + "\n" + str(messages))

if __name__ == "__main__":
    
    print("""?
     ____.  _____  ________  ____  ___    _____  ___________________  _________ .__  .__               __   
    |    | /  _  \ \______ \ \   \/  /   /     \ \_   ___ \______   \ \_   ___ \|  | |__| ____   _____/  |_ 
    |    |/  /_\  \ |    |  \ \     /   /  \ /  \/    \  \/|     ___/ /    \  \/|  | |  |/ __ \ /    \   __\\
/\__|    /    |    \|    `   \/     \  /    Y    \     \___|    |     \     \___|  |_|  \  ___/|   |  \  |  
\________\____|__  /_______  /___/\  \ \____|__  /\______  /____|      \______  /____/__|\___  >___|  /__|  
                 \/        \/      \_/         \/        \/                   \/             \/     \/      
                    """)
    
    asyncio.run(main())