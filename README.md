# Detection and Exploitation of Vulnerabilities in Android Applications Using Large Language Models and Model Context Protocol

This repository contains the code for my master's thesis project, _Detection and Exploitation of Vulnerabilities in Android Applications Using Large Language Models and Model Context Protocol_. This repository includes the two agents implemented in the code directory, as well as the templates for the rules and the verification scripts.

This project is structured into two parts: in the first part, I leverage LLMs and MCP servers to detect violations of Google security guidelines in Android applications. In the second part, I generate Proof-of-Concept (PoC) exploits to test whether the violations are exploitable. 

Both agents were tested against 10 real-world applications that have already been analyzed with the static analysis tool [SPECK](https://github.com/SPRITZ-Research-Group/SPECK), and 31 rules defined from the [Google Security Guidelines](https://developer.android.com/privacy-and-security/security-tips). 

For the vulnerability detection part, I gave each rule to the LLM, along with the APK file decompiled with JADX (using the JADX MCP server to extract the code), and asked it to detect rule violations. I compared the results with the results of SPECK. 

For the exploit generation part, the agent developed attacks affecting insecure manifest components and network communication: I submitted the rule, the target violation found by SPECK, and the LLM analyzed the decompiled APK file to edit the PoC template, then the edited template was used to verify whether the vulnerability is exploitable. 

For the overall results, the detection agent achieved a mean precision of 63.90% and a mean recall of 53.97%. For the Automated Exploit Generation part, I achieved a PoC success rate of 30.45% across 266 vulnerabilities.

The full thesis can be found [here](./thesis.pdf). The code is available under the MIT License.
