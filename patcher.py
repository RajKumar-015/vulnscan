import re
import ollama


SYSTEM_PROMPT = r"""
You are VulnScan's defensive C/C++ security remediation engine.

Fix ONLY the vulnerability identified in the supplied CWE and static-analysis evidence.

Rules:
1. The ORIGINAL SOURCE CODE is the source of truth.
2. Identify the exact vulnerable operation.
3. Make the smallest security fix possible.
4. Preserve the program's original behavior.
5. Do not redesign the program.
6. Do not invent vulnerabilities or previous patches.
7. Do not add unnecessary input operations.
8. Never call an input function twice accidentally.
9. Never replace one unsafe operation with another.
10. Keep all buffer accesses within bounds.
11. Properly NUL-terminate strings when required.
12. Do not introduce uninitialized variables or invalid pointer arithmetic.
13. Use C/C++ library functions with their correct return types.
14. The complete patched source must be valid and compilable C/C++.

For a buffer overflow caused by strcpy(), strcat(), sprintf(), gets(),
or another unsafe string operation, fix that operation directly.
Do not redesign the input logic.

Example:
char buffer[10];
char input[100];
strcpy(buffer, input);

must become a genuinely bounded copy with correct NUL termination,
or another equally safe minimal solution.

Do NOT invent functions such as strtok_r() or sscanf() unless they are
actually required by the original source.

Return exactly:

EXPLANATION:
<short explanation>

PATCHED CODE:
```c
<complete corrected source>
```

CHANGES:
<short description>
"""


def _extract_section(text: str, heading: str, next_headings: list[str]) -> str:
    """
    Extract a section even if Llama decorates headings with:
      EXPLANATION:
      ===== EXPLANATION =====
      **EXPLANATION:**
      EXPLANATION
    """
    heading_pattern = re.escape(heading)

    start = re.search(
        rf"(?:^|\n)\s*(?:[#*_=\-]+\s*)?{heading_pattern}\s*:?\s*(?:[#*_=\-]+)?\s*\n?",
        text,
        re.IGNORECASE,
    )

    if not start:
        return ""

    start_pos = start.end()
    end_pos = len(text)

    for next_heading in next_headings:
        m = re.search(
            rf"(?:^|\n)\s*(?:[#*_=\-]+\s*)?{re.escape(next_heading)}\s*:?\s*(?:[#*_=\-]+)?\s*\n?",
            text[start_pos:],
            re.IGNORECASE,
        )
        if m:
            end_pos = min(end_pos, start_pos + m.start())

    return text[start_pos:end_pos].strip()


def _clean_code(code: str) -> str:
    code = code.strip()

    # Remove markdown fences and accidental language labels.
    code = re.sub(r"^\s*```(?:c|cpp|c\+\+|C|C\+\+)?\s*", "", code)
    code = re.sub(r"\s*```\s*$", "", code)

    # Remove a second layer of fences if the model duplicated them.
    code = code.replace("```c", "").replace("```cpp", "")
    code = code.replace("```c++", "").replace("```", "")

    return code.strip()


def _fallback_code(text: str) -> str:
    """
    If the model did not use the required heading format, recover the
    largest C/C++ code fence from the response.
    """
    blocks = re.findall(
        r"```(?:c|cpp|c\+\+)?\s*(.*?)```",
        text,
        re.DOTALL | re.IGNORECASE,
    )

    if blocks:
        # Prefer a block containing a C/C++ entry point or include.
        ranked = sorted(
            blocks,
            key=lambda b: (
                ("#include" in b),
                ("main(" in b),
                len(b),
            ),
            reverse=True,
        )
        return _clean_code(ranked[0])

    # Last-resort extraction from #include through the end.
    include_pos = text.find("#include")
    if include_pos >= 0:
        candidate = text[include_pos:].strip()

        # Remove trailing CHANGES if present.
        candidate = re.split(
            r"\n\s*(?:[#*_=\-]+\s*)?CHANGES\s*:?",
            candidate,
            maxsplit=1,
            flags=re.IGNORECASE,
        )[0]

        return _clean_code(candidate)

    return ""


def patch_code(prompt: str) -> dict:
    print("\nSending vulnerable code to LLaMA for security remediation...\n")

    try:
        response = ollama.chat(
            model="llama3.2:3b",
            messages=[
                {
                    "role": "system",
                    "content": SYSTEM_PROMPT,
                },
                {
                    "role": "user",
                    "content": prompt,
                },
            ],
        )
    except Exception as e:
        print(f"LLM error: {e}")
        return {
            "explanation": "",
            "patched_code": "",
            "changes": "",
            "full_response": "",
            "error": str(e),
        }

    text = response["message"]["content"]

    print("\n===== RAW LLM RESPONSE =====")
    print(text)
    print("===== END RAW LLM RESPONSE =====\n")

    explanation = _extract_section(
        text,
        "EXPLANATION",
        ["PATCHED CODE", "CHANGES"],
    )

    patched_code = _extract_section(
        text,
        "PATCHED CODE",
        ["CHANGES"],
    )

    changes = _extract_section(
        text,
        "CHANGES",
        [],
    )

    patched_code = _clean_code(patched_code)

    # Llama sometimes adds decorative headings that defeat simple parsers.
    if not patched_code:
        patched_code = _fallback_code(text)

    if not explanation:
        explanation = "No structured explanation was returned by the LLM."

    if not changes:
        changes = "No structured changes section was returned by the LLM."

    if not patched_code:
        error = (
            "LLM returned a response, but no C/C++ source code could be "
            "reliably extracted from it."
        )
    else:
        error = ""

    return {
        "explanation": explanation,
        "patched_code": patched_code,
        "changes": changes,
        "full_response": text,
        "error": error,
    }