CWE_DESCRIPTIONS = {
    "CWE-120": "Buffer Overflow - copying data without checking buffer size",
    "CWE-119": "Improper Restriction of Buffer Operations",
    "CWE-401": "Memory Leak - memory allocated but never freed",
    "CWE-416": "Use After Free - using memory after it has been freed",
    "CWE-476": "NULL Pointer Dereference",
    "CWE-457": "Use of Uninitialized Variable",
}

def build_prompt(code: str, cwes: list, flawfinder_findings: list) -> str:
    cwe_info = ""
    for cwe in cwes:
        desc = CWE_DESCRIPTIONS.get(cwe, "Unknown vulnerability type")
        cwe_info += f"  - {cwe}: {desc}\n"

    risky_calls = []
    for finding in flawfinder_findings:
        if "strcpy" in finding:
            risky_calls.append("strcpy")
        if "strcat" in finding:
            risky_calls.append("strcat")
        if "sprintf" in finding:
            risky_calls.append("sprintf")
        if "gets" in finding:
            risky_calls.append("gets")
        if "scanf" in finding:
            risky_calls.append("scanf")

    risky_calls = list(set(risky_calls))

    prompt = f"""You are a C/C++ security expert. Analyze the vulnerable code below and generate a secure patched version.

VULNERABILITY DETAILS:
{cwe_info}
RISKY CALLS DETECTED: {', '.join(risky_calls) if risky_calls else 'See code below'}

VULNERABLE CODE:
{code}

INSTRUCTIONS:
1. Identify exactly why this code is vulnerable
2. Generate a complete secure patched version
3. Explain what you changed and why

Respond in this format:
EXPLANATION: <why the code is vulnerable>
PATCHED CODE:
<complete patched function>
CHANGES: <what you changed>
"""
    return prompt


if __name__ == "__main__":
    test_code = """
    void processInput(char *input) {
        char dest[64];
        strcpy(dest, input);
    }
    """
    cwes = ["CWE-120", "CWE-119"]
    findings = ["temp_code.c:5:  [4] (buffer) strcpy:"]

    prompt = build_prompt(test_code, cwes, findings)
    print(prompt)