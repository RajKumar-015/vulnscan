# 🔐 VulnScan

### Automated C/C++ Vulnerability Detection & AI-Assisted Patching

VulnScan is an end-to-end security analysis tool for detecting vulnerabilities in C/C++ source code, identifying relevant CWE categories, generating AI-assisted patches, and verifying the resulting code using static analysis.

The system combines **CodeBERT-based vulnerability classification**, **Flawfinder**, **Cppcheck**, and a **locally running Llama 3.2 3B model through Ollama** into a single analysis and remediation pipeline.

---

## ✨ Features

- 🔍 **ML-based vulnerability detection** using CodeBERT
- 🛡️ **Static security analysis** with Flawfinder
- 🔎 **AST-based static analysis** with Cppcheck
- 🧠 **Hybrid vulnerability decision** combining ML and static-analysis evidence
- 🏷️ **CWE identification** from static-analysis findings
- 🤖 **Local LLM-based patch generation** using Llama 3.2 3B
- 🔧 **Automated vulnerability remediation**
- ✅ **Patch verification** using Cppcheck
- 📊 Interactive **Streamlit dashboard**
- 📁 Supports **C, C++, and header files**
- 🔒 LLM inference runs locally through **Ollama**

---

# 🏗️ System Architecture

VulnScan follows a multi-stage detection and remediation pipeline:

```text
                     ┌─────────────────────┐
                     │   C / C++ Source    │
                     │ Upload or Paste Code │
                     └──────────┬──────────┘
                                │
                                ▼
                     ┌─────────────────────┐
                     │      CodeBERT        │
                     │ Vulnerability Model  │
                     └──────────┬──────────┘
                                │
                                ▼
              ┌──────────────────────────────────┐
              │        Static Analysis            │
              │                                  │
              │   Flawfinder + Cppcheck          │
              └────────────────┬─────────────────┘
                               │
                               ▼
                     ┌─────────────────────┐
                     │  Hybrid Decision    │
                     │  + CWE Extraction   │
                     └──────────┬──────────┘
                                │
                         Vulnerability?
                                │
                                ▼
                     ┌─────────────────────┐
                     │   Prompt Builder    │
                     │ Structured Context  │
                     └──────────┬──────────┘
                                │
                                ▼
                     ┌─────────────────────┐
                     │   Llama 3.2 3B      │
                     │      Ollama          │
                     └──────────┬──────────┘
                                │
                                ▼
                     ┌─────────────────────┐
                     │   Generated Patch   │
                     └──────────┬──────────┘
                                │
                                ▼
                     ┌─────────────────────┐
                     │  Patch Verification │
                     │      Cppcheck       │
                     └──────────┬──────────┘
                                │
                                ▼
                     ┌─────────────────────┐
                     │ Security Assessment │
                     │ + Patch + Report     │
                     └─────────────────────┘
🔄 Pipeline
1. Input

Users can either:

Upload a C/C++ source file
Paste source code directly into the interface

Supported extensions include:

.c
.cpp
.h
2. ML Vulnerability Detection

CodeBERT analyzes the source code and predicts whether it contains insecure code.

The project uses:

mrm8488/codebert-base-finetuned-detect-insecure-code

The model provides:

Vulnerability classification
Confidence score
3. Static Analysis

Two complementary static-analysis tools are used:

Flawfinder

Detects potentially dangerous C/C++ functions and security-sensitive patterns.

Cppcheck

Performs deeper static analysis and identifies potential programming and security issues.

4. Hybrid Decision

VulnScan combines:

CodeBERT Prediction
        +
Flawfinder Findings
        +
Cppcheck Findings
        ↓
Hybrid Security Decision

This provides additional evidence instead of relying solely on the ML model.

5. CWE Identification

Static-analysis findings are processed to identify relevant CWE categories associated with the detected vulnerability.

Example:

CWE-119
CWE-120
CWE-20
6. AI-Assisted Patching

When a vulnerability is confirmed, VulnScan constructs a structured remediation prompt containing the relevant source code and security findings.

The prompt is sent to:

Ollama
   ↓
Llama 3.2 3B

The model generates:

Vulnerability explanation
Patched source code
Description of changes
7. Patch Verification

The generated patch is passed through the verification stage.

Cppcheck is used to determine whether the patched code still contains relevant issues.

The application then reports whether the remediation was successfully verified.

🛠️ Tech Stack
Component	Technology
Frontend / UI	Streamlit
Programming Language	Python
ML Model	CodeBERT
ML Framework	Hugging Face Transformers
Security Analysis	Flawfinder
Static Analysis	Cppcheck
LLM Runtime	Ollama
LLM	Llama 3.2 3B
Target Languages	C / C++
📁 Project Structure
vulnscan/
│
├── app.py                 # Streamlit application
├── main.py                # Main pipeline entry point
├── detector.py            # ML + static-analysis detection
├── prompt_builder.py      # LLM prompt construction
├── patcher.py             # LLM patch generation and extraction
├── verifier.py            # Patch verification
│
├── samples/
│   └── vulnerable_buffer.c
│
├── docs/
│   ├── Explanation.png
│   ├── dashboard.png
│   ├── patched.png
│   └── verification.png
│
├── requirements.txt
├── LICENSE
├── .gitignore
└── README.md
🚀 Installation
1. Clone the repository
git clone https://github.com/RajKumar-015/vulnscan.git
cd vulnscan
2. Create a virtual environment
Windows
python -m venv .venv
.venv\Scripts\activate
macOS / Linux
python3 -m venv .venv
source .venv/bin/activate
3. Install Python dependencies
pip install -r requirements.txt
🔧 System Dependencies

VulnScan requires the following tools:

Python 3.10+
Flawfinder
Cppcheck
Ollama

Verify the installations:

flawfinder --version
cppcheck --version
ollama --version
🤖 Setup Llama 3.2 3B

Install Ollama and download the required model:

ollama pull llama3.2:3b

Make sure Ollama is running before starting an analysis that requires LLM patch generation.

▶️ Run VulnScan

Start the Streamlit application:

streamlit run app.py

Streamlit will provide a local URL, normally:

http://localhost:8501

Open the URL in your browser.

🧪 Test With the Included Sample

A vulnerable C program is included:

samples/vulnerable_buffer.c

The sample demonstrates unsafe input handling involving functions such as:

gets()
strcpy()

Upload the sample through the VulnScan interface and select:

Analyze & Patch Vulnerabilities

The application will execute the detection and remediation pipeline.

📊 Example Workflow
Vulnerable C Code
       │
       ▼
   CodeBERT
       │
       ▼
Flawfinder + Cppcheck
       │
       ▼
Hybrid Vulnerability Decision
       │
       ▼
    CWE IDs
       │
       ▼
Prompt Builder
       │
       ▼
Llama 3.2 3B
       │
       ▼
   Patched Code
       │
       ▼
   Cppcheck
       │
       ▼
Verification Result
🖥️ Screenshots
Dashboard

Vulnerability Explanation

Patched Code

Verification

🔐 Example Detection

For a vulnerable buffer-handling program, VulnScan can identify security issues associated with unsafe memory operations.

Example output:

Security Decision:
CONFIRMED VULNERABLE

Confidence:
HIGH

Detected CWEs:
CWE-119
CWE-120
CWE-20

The remediation stage then generates a candidate secure implementation and sends it through the verification stage.

⚠️ Limitations

VulnScan is intended as a security research and engineering project rather than a replacement for professional security auditing.

Current limitations include:

Detection depends on the capabilities of the underlying ML and static-analysis tools.
LLM-generated patches are candidate remediations and should be reviewed before production use.
Patch verification currently relies primarily on Cppcheck-based validation.
LLM inference performance depends on the available local hardware.
CWE mapping is currently based on available static-analysis evidence.
🔮 Future Improvements

Potential future improvements include:

AST-based vulnerability localization
More comprehensive CWE mapping
Compiler-based patch validation
Automated regression testing
Patch diff generation
Expanded vulnerability classes
Benchmark-based evaluation
Multi-file project analysis
Automated test generation for generated patches
More comprehensive C/C++ security datasets
📌 Project Goals

VulnScan explores how machine learning, static analysis, and local LLMs can work together to automate parts of the vulnerability remediation workflow.

Rather than relying on a single detection technique, the system combines multiple sources of evidence before generating and verifying a remediation.

👨‍💻 Author

Raj Kumar

CSE Student | Software Development | Security & AI

📄 License

This project is licensed under the MIT License.
