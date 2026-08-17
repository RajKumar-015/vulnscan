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
        description = CWE_DESCRIPTIONS.get(cwe, "Unknown vulnerability type")
        cwe_info += f"- {cwe}: {description}\n"

    if not cwe_info:
        cwe_info = "No CWE information was provided."

    risky_calls = []

    for finding in flawfinder_findings:
        finding_lower = finding.lower()

        for call in ["strcpy", "strcat", "sprintf", "gets", "scanf"]:
            if call in finding_lower:
                risky_calls.append(call)

    risky_calls = sorted(set(risky_calls))

    risky_calls_text = (
        ", ".join(risky_calls)
        if risky_calls
        else "None explicitly identified"
    )

    findings_text = (
        "\n".join(flawfinder_findings)
        if flawfinder_findings
        else "No Flawfinder findings available."
    )

    # Use concatenated strings instead of a triple-quoted f-string.
    # This avoids accidental unterminated-string errors while keeping
    # the prompt easy to maintain.
    prompt = (
        "VULNSCAN SECURITY REMEDIATION TASK\n\n"
        "You are a defensive C/C++ security remediation engine.\n\n"
        "==================================================\n"
        "ORIGINAL SOURCE CODE\n"
        "==================================================\n\n"
        "```c\n"
        + code
        + "\n```\n\n"
        "==================================================\n"
        "IDENTIFIED VULNERABILITIES\n"
        "==================================================\n\n"
        + cwe_info
        + "\n"
        "==================================================\n"
        "STATIC ANALYSIS EVIDENCE\n"
        "==================================================\n\n"
        "RISKY CALLS DETECTED:\n"
        + risky_calls_text
        + "\n\n"
        "FLAWFINDER FINDINGS:\n"
        + findings_text
        + "\n\n"
        "==================================================\n"
        "CORE REMEDIATION RULE\n"
        "==================================================\n\n"
        "The ORIGINAL SOURCE CODE is the source of truth.\n"
        "Fix ONLY the vulnerability identified by the supplied CWE "
        "and static-analysis evidence.\n"
        "Do NOT invent vulnerabilities that are not present.\n"
        "Do NOT redesign or rewrite the program.\n"
        "Do NOT change unrelated functionality.\n"
        "Make the smallest reasonable security modification.\n"
        "Preserve the original program's purpose and behavior.\n\n"
        "SECURITY REQUIREMENTS:\n"
        "1. Identify the exact vulnerable operation.\n"
        "2. Fix that operation directly.\n"
        "3. Do not replace one unsafe operation with another.\n"
        "4. Do not introduce new vulnerabilities.\n"
        "5. Do not introduce unnecessary input operations.\n"
        "6. Do not call input functions twice accidentally.\n"
        "7. Do not introduce uninitialized variables.\n"
        "8. Do not introduce invalid pointer arithmetic.\n"
        "9. Keep all buffer accesses within bounds.\n"
        "10. Properly NUL-terminate strings when required.\n"
        "11. Preserve existing structure whenever possible.\n"
        "12. Do not add unnecessary libraries.\n"
        "13. The complete source must be valid C/C++.\n"
        "14. The generated source must reasonably compile.\n\n"
        "BUFFER OVERFLOW RULE:\n"
        "If the vulnerability is caused by strcpy(), strcat(), "
        "sprintf(), gets(), or another unsafe string operation, "
        "fix that operation directly. Do not redesign the input system. "
        "Use a correctly bounded approach and ensure NUL termination.\n\n"
        "FUNCTION RETURN VALUES:\n"
        "Use C/C++ library functions according to their real signatures. "
        "For example, strncpy() returns a char pointer, not a character count. "
        "Never assign its return value to size_t when you mean copied length.\n\n"
        "DO NOT INVENT PREVIOUS PATCHES:\n"
        "There is no previous patch unless one is explicitly supplied. "
        "Do not claim that strtok_r(), sscanf(), or another function was "
        "previously used unless it actually appears in the supplied source.\n\n"
        "FINAL SELF-CHECK:\n"
        "Before returning, verify: exact CWE fixed; vulnerable operation "
        "removed or constrained; behavior preserved; buffers bounded; "
        "strings terminated; no duplicate input calls; no new vulnerability; "
        "correct library return types; valid syntax; compilable source; "
        "minimal changes.\n\n"
        "==================================================\n"
        "REQUIRED RESPONSE FORMAT\n"
        "==================================================\n\n"
        "EXPLANATION:\n"
        "Explain the exact vulnerability, vulnerable operation, and fix.\n\n"
        "PATCHED CODE:\n"
        "Return the COMPLETE corrected C/C++ source code. "
        "Do not return pseudocode or multiple alternatives.\n\n"
        "CHANGES:\n"
        "Briefly describe ONLY the security-related changes.\n"
        "Return exactly these three sections.\n"
    )

    return prompt


if __name__ == "__main__":
    test_code = """
#include <stdio.h>
#include <string.h>

void processInput(char *input) {
    char dest[64];
    strcpy(dest, input);
}
"""

    cwes = ["CWE-120", "CWE-119"]
    findings = ["temp_code.c:5: [4] (buffer) strcpy:"]

    prompt = build_prompt(test_code, cwes, findings)
    print(prompt)