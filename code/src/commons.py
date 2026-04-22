import os
import logfire
import yaml
from utils.llm_utils import ReasoningEffort
from pydantic_ai.models.openai import OpenAIChatModel, OpenAIResponsesModelSettings
from pydantic_ai.providers.ollama import OllamaProvider
from pydantic_ai.models.google import GoogleModel
from pydantic_ai.providers.google import GoogleProvider
from pydantic_ai.models.anthropic import AnthropicModel

PATH = os.path.dirname(os.path.abspath(__file__))

config_file = open(PATH + "/../config.yaml", "r")
config = yaml.safe_load(config_file)

def configure_logfire():
    logfire.configure()
    logfire.instrument_pydantic_ai()

    def scrubbing_callback(m: logfire.ScrubMatch):
        return m.value

    logfire.configure(scrubbing=logfire.ScrubbingOptions(callback=scrubbing_callback))

def get_single_rule(rule_number):
    speck_guidelines = open(PATH + "../SPECK_guidelines.md", "r").read()

    speck_guidelines_idx = speck_guidelines.find("## A.{} Rule {}".format(rule_number, rule_number))
    speck_guidelines_idx_end = speck_guidelines.find("## A.{} Rule {}".format(rule_number + 1, rule_number + 1))

    if speck_guidelines_idx == -1:
        raise ValueError(f"Rule {rule_number} is not a valid rule.")
    
    if speck_guidelines_idx_end != -1:
        return speck_guidelines[speck_guidelines_idx:speck_guidelines_idx_end]
    else:
        return speck_guidelines[speck_guidelines_idx:]
    
def get_model(args):
    model = None

    if args.remote == True:
        model = OpenAIChatModel(config.models.openai)
    elif args.claude == True:
        model = AnthropicModel(config.models.anthropic)
    elif args.gemini == True:
        provider = GoogleProvider()
        model = GoogleModel(config.models.gemini, provider=provider)
    else:
        provider = OllamaProvider()
        model = OpenAIChatModel(
            model_name=config.models.ollama,
            provider=provider
        )

    return model

def get_package_name(manifest):
    package_name = ""
    for line in manifest["content"]:
        if "package=" in line:
            package_name = line.split('package="')[1].split('"')[0]
            break
    return package_name

def get_parameters_and_settings():
    parameters = {
        "temperature": config.parameters.temperature,
        "presence_penalty": config.parameters.presence_penalty,
        "frequency_penalty": config.parameters.frequency_penalty,
        "reasoning_effort": ReasoningEffort(config.parameters.reasoning_effort),
        "reasoning_summary": "concise",
        "top_p": 1.0,
    }
    settings = OpenAIResponsesModelSettings(
        temperature=parameters["temperature"],
        openai_reasoning_effort=parameters["reasoning_effort"],
        openai_reasoning_summary=parameters["reasoning_summary"],
        top_p=parameters["top_p"],
    )
    return parameters, settings