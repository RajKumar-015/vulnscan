import ollama
import re


def patch_code(prompt: str) -> dict:
    print("\nSending to LLaMA for patching... (may take 2-3 min)\n")

    # Try the local Ollama server.
    # If Ollama is unavailable (for example, on Streamlit Cloud),
    # return a graceful response instead of crashing the application.
    try:
        response = ollama.chat(
            model="llama3.2:3b",
            messages=[
                {
                    "role": "system",
                    "content": (
                        "You are a C/C++ security expert. "
                        "Always respond with EXPLANATION, PATCHED CODE and CHANGES sections."
                    )
                },
                {
                    "role": "user",
                    "content": prompt
                }
            ]
        )

    except Exception as e:
        print(f"Ollama unavailable: {e}")

        return {
            "explanation": (
                "AI patch generation is unavailable in this deployment. "
                "VulnScan's detection and static-analysis pipeline completed "
                "successfully, but the local Ollama server required for "
                "Llama 3.2 3B is not available. "
                "Run VulnScan locally with Ollama enabled to generate an AI-assisted patch."
            ),
            "patched_code": "",
            "changes": (
                "No patch was generated because the local Ollama LLM "
                "is unavailable in the current environment."
            ),
            "full_response": ""
        }

    text = response["message"]["content"]

    # Extract sections using robust regex handling
    explanation = ""
    patched_code = ""
    changes = ""

    # Explanation
    exp_match = re.search(
        r"EXPLANATION:(.*?)(?:PATCHED CODE:|CHANGED CODE:|$)",
        text,
        re.DOTALL | re.IGNORECASE
    )

    if exp_match:
        explanation = exp_match.group(1).strip()

    # Patched code – try fenced block first
    code_match = re.search(
        r"(?:PATCHED CODE:|CHANGED CODE:)\s*```[a-zA-Z0-9+#.-]*\n?(.*?)```",
        text,
        re.DOTALL | re.IGNORECASE
    )

    if not code_match:
        # Fallback to non-fenced version
        code_match = re.search(
            r"(?:PATCHED CODE:|CHANGED CODE:)\s*(.*?)(?:CHANGES:|$)",
            text,
            re.DOTALL | re.IGNORECASE
        )

    if code_match:
        patched_code = code_match.group(1).strip()

    # Changes
    changes_match = re.search(
        r"CHANGES:(.*)",
        text,
        re.DOTALL | re.IGNORECASE
    )

    if changes_match:
        changes = changes_match.group(1).strip()

    return {
        "explanation": explanation,
        "patched_code": patched_code,
        "changes": changes,
        "full_response": text
    }


if __name__ == "__main__":
    from prompt_builder import build_prompt

    test_code = """
    void processInput(char *input) {
        char dest[64];
        strcpy(dest, input);
    }
    """

    cwes = ["CWE-120", "CWE-119"]
    findings = ["temp_code.c:5:  [4] (buffer) strcpy:"]

    prompt = build_prompt(test_code, cwes, findings)
    result = patch_code(prompt)

    print("=" * 50)
    print("EXPLANATION:")
    print(result["explanation"])

    print("\nPATCHED CODE:")
    print(result["patched_code"])

    print("\nCHANGES:")
    print(result["changes"])