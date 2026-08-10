import ollama
import re


def patch_code(prompt: str) -> dict:
    print("\n Sending to LLaMA for patching... (may take 2-3 min)\n")

    response = ollama.chat(
        model="llama3.2:3b",
        messages=[
            {
                "role": "system",
                "content": "You are a C/C++ security expert. Always respond with EXPLANATION, PATCHED CODE and CHANGES sections."
            },
            {
                "role": "user",
                "content": prompt
            }
        ]
    )

    text = response['message']['content']

    # extract sections using robust regex handling
    explanation = ""
    patched_code = ""
    changes = ""

    # Explanation
    exp_match = re.search(r"EXPLANATION:(.*?)(?:PATCHED CODE:|CHANGED CODE:|$)", text, re.DOTALL)
    if exp_match:
        explanation = exp_match.group(1).strip()

    # Patched code – try fenced block first
    code_match = re.search(r"PATCHED CODE:\s*```[a-z]*\n?(.*?)```", text, re.DOTALL)
    if not code_match:
        # fallback to non‑fenced version up to CHANGES or end
        code_match = re.search(r"(?:PATCHED CODE:|CHANGED CODE:)\s*(.*?)(?:CHANGES:|$)", text, re.DOTALL)
    if code_match:
        patched_code = code_match.group(1).strip()

    # Changes
    changes_match = re.search(r"CHANGES:(.*)", text, re.DOTALL)
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
    print(result['explanation'])
    print("\nPATCHED CODE:")
    print(result['patched_code'])
    print("\nCHANGES:")
    print(result['changes'])