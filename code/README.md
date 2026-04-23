# Agents Source Code

This folder contains the source code of the two agents implemented for the thesis project. The first agent is responsible for detecting vulnerabilities in Android applications using LLMs and the [JADX AI MCP Plugin](https://github.com/zinja-coder/jadx-ai-mcp), while the second agent is responsible for generating Proof-of-Concept (PoC) exploits to test whether the detected vulnerabilities are exploitable. For setting up the LLM and querying it, I used [Pydantic AI](https://pydantic.dev/docs/ai/overview/) to define the expected output format and to set up the MCP connection. 

## Requirements

- Python 3.14 or higher
- JADX
- JADX AI MCP Plugin (and the [JADX MCP Server](https://github.com/zinja-coder/jadx-mcp-server))

Additionally for exploit generation, the following tools are required (and should be present in the system PATH):
- Android SDK (for adb and other tools)
- Android Build Tools version 33 (for apksigner, zipalign, etc.)
- Android Emulator
- APKtool (for repackaging APKs)
- mitmproxy and mitmdump (for network traffic analysis attacks)

## Installation

[uv](https://docs.astral.sh/uv/) is recommended for managing the project and it's dependencies. Initialize a new environment in the project directory:

```bash
uv venv
```

Install the required Python packages:

```bash
uv pip install -r pyproject.toml
```

Then access the `src` folder to find the source code of the agents.

```bash
cd src
```

Inside the `src` folder, you will find two main files: `detect.py` for the detection agent and `exploit.py` for the exploitation agent. Each of these files can be run independently to perform their respective tasks.

First change the location of the MCP server in the `server_configs.json` file, then you can run the agents using the following commands:

```bash
uv run detect.py
```

```bash
uv run exploit.py
```

## Usage

To use the agents, simply run the respective Python scripts as shown above. The detection agent will analyze the provided Android application and identify potential vulnerabilities, the vulnerabilities found will be saved to a JSON (inside the `violations` directory) file which can then be passed to the exploitation agent, which will attempt to generate PoC exploits for the detected vulnerabilities.

The generated exploits will be saved in the `src/exploit-pocs` directory, they can be executed by starting the Python script `verify.py`, the agent will also try to run the generated exploits.

Make sure to have JADX and the JADX MCP Server running and properly configured before executing the agents, as they rely on it for code analysis.

Additionally for the exploitation agent, it is recommended to put the APKs under analysis in the `apks` directory.

## Command Line Arguments

For the vulnerability detection agent (`detect.py`), the following command line arguments are available:

```bash
-h, --help            show this help message and exit
--remote, -oai, -gpt  Use an OpenAI model
--gemini, -g          Use a Google Model
--claude, -c          Use an Anthropic model
--runs, -rn RUNS      How many runs to be done (default is 4)
--rule, -r RULE       The rule number to test
```

For the exploit generation agent (`exploit.py`), the following command line arguments are available:

```bash
-h, --help            show this help message and exit
--remote, -oai, -gpt  Use an OpenAI model
--gemini, -g          Use a Google Model
--claude, -c          Use an Anthropic model
--rule, -r RULE       The rule number to test
```

## Configuration

Models and parameters used by the agents can be configured in the `config.yaml` file. This file allows you to specify which LLMs to use for each provider, as well as various parameters that influence the behavior of the agents, such as temperature, presence penalty, frequency penalty, and reasoning effort.

Environment variables for API keys and other sensitive information should be set according to the requirements of the LLMs you intend to use. For example, if you are using OpenAI's models, you will need to set the `OPENAI_API_KEY` environment variable with your OpenAI API key.

The supported providers are:
- OpenAI
- Anthropic
- Google
- Ollama

For exploit generation the following additional environment variables are required:
- `ANDROID_AVD`: the name of the Android Virtual Device (AVD) to be used for testing exploits on an emulator.
- `PROXY_IP`: the IP address of the machine running mitmdump, used for network traffic analysis attacks.
- `PROXY_PORT`: the port number on which mitmdump is listening, used for network traffic analysis attacks.
- `ANDROID_HOME`: the path to the Android SDK, used for building and deploying repackaged APKs (optional).

For generating exploits for network communication vulnerabilities, it is also necessary to create fake SSL certificates for the target application and install them on the testing device (emulator or physical device). The files should be placed in the `certs` directory with the name `fake_cert.pem` and `fake_key.pem`.