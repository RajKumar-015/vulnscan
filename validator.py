import ollama
import re


VALIDATION_SYSTEM_PROMPT = """You are a C/C++ vulnerability triage expert.
You are a SECONDARY VALIDATOR, not a patch generator.

The first-stage ML model has flagged the source as suspicious, but static
security analyzers did not identify a mapped CWE.

Your job is to determine whether the source contains a REAL security
vulnerability that warrants remediation.

Be conservative:
- Do not call normal input handling, constant printf format strings,
  ordinary library usage, or harmless code vulnerable.
- Do not invent a vulnerability just because user input exists.
- Only confirm when you can point to a concrete unsafe operation and explain
  the security impact.

Respond using exactly these sections:

VERDICT: CONFIRMED
or
VERDICT: FALSE_POSITIVE
or
VERDICT: UNCERTAIN

REASON:
<short technical explanation>

CWE:
CWE-<number> if you can identify the relevant weakness, otherwise NONE

EVIDENCE:
<specific line/pattern that supports your verdict, or "None">
"""



def _obvious_safe_input_pattern(code: str) -> bool:
    """
    Conservative rule for a common safe pattern:
    bounded fgets() into a declared buffer, followed by a normal %s print.
    This prevents the secondary LLM validator from hallucinating a CWE for
    clearly bounded input handling.

    This is intentionally narrow; it does NOT replace CodeBERT or static
    analysis for other code.
    """
    normalized = re.sub(r"\s+", " ", code)

    has_bounded_fgets = bool(
        re.search(
            r"fgets\s*\(\s*\w+\s*,\s*sizeof\s*\(\s*\w+\s*\)\s*,\s*stdin\s*\)",
            normalized,
            re.IGNORECASE,
        )
    )

    has_normal_string_print = bool(
        re.search(r'printf\s*\(\s*"%s"\s*,\s*\w+\s*\)', normalized)
        or re.search(r'printf\s*\(\s*"%s[^"]*"\s*,\s*\w+\s*\)', normalized)
    )

    dangerous_operations = re.search(
        r"\b(strcpy|strcat|sprintf|vsprintf|gets|scanf|sscanf|memcpy|memmove)\s*\(",
        normalized,
        re.IGNORECASE,
    )

    return has_bounded_fgets and has_normal_string_print and not dangerous_operations


def validate_ml_suspect(code: str) -> dict:
    """Secondary semantic validation for CodeBERT-only detections."""

    # Resolve an obvious safe pattern deterministically before invoking the
    # LLM. The ML model remains an independent signal; this only prevents a
    # known-safe bounded-input pattern from being hallucinated as vulnerable.
    if _obvious_safe_input_pattern(code):
        return {
            "available": True,
            "verdict": "FALSE_POSITIVE",
            "cwe": "NONE",
            "reason": (
                "The source uses bounded fgets() with sizeof(buffer) and prints "
                "the resulting string with a fixed %s format. No unsafe string "
                "copy or unbounded input operation was identified."
            ),
            "evidence": "fgets(buffer, sizeof(buffer), stdin)",
            "raw_response": "Deterministic safe-pattern validation",
            "error": "",
        }

    try:
        response = ollama.chat(
            model="llama3.2:3b",
            messages=[
                {"role": "system", "content": VALIDATION_SYSTEM_PROMPT},
                {
                    "role": "user",
                    "content": (
                        "Review this C/C++ source code:\n\n"
                        "```c\n"
                        f"{code}\n"
                        "```\n\n"
                        "The ML detector flagged it as suspicious, while "
                        "static analysis found no mapped security CWE."
                    ),
                },
            ],
        )

        text = response["message"]["content"].strip()

    except Exception as exc:
        return {
            "available": False,
            "verdict": "UNAVAILABLE",
            "reason": (
                "Secondary validation could not run because the local Ollama "
                "LLM is unavailable in this environment."
            ),
            "evidence": "",
            "raw_response": "",
            "error": str(exc),
        }

    verdict_match = re.search(
        r"VERDICT\s*:\s*(CONFIRMED|FALSE_POSITIVE|UNCERTAIN)",
        text,
        re.IGNORECASE,
    )
    reason_match = re.search(
        r"REASON\s*:\s*(.*?)(?:EVIDENCE\s*:|$)",
        text,
        re.DOTALL | re.IGNORECASE,
    )
    cwe_match = re.search(
        r"CWE\s*:\s*(CWE-\d+|NONE)",
        text,
        re.IGNORECASE,
    )
    evidence_match = re.search(
        r"EVIDENCE\s*:\s*(.*)$",
        text,
        re.DOTALL | re.IGNORECASE,
    )

    verdict = verdict_match.group(1).upper() if verdict_match else "UNCERTAIN"
    reason = reason_match.group(1).strip() if reason_match else "No reason returned."
    cwe = cwe_match.group(1).upper() if cwe_match else "NONE"
    evidence = evidence_match.group(1).strip() if evidence_match else "None"

    return {
        "available": True,
        "verdict": verdict,
        "cwe": cwe,
        "reason": reason,
        "evidence": evidence,
        "raw_response": text,
        "error": "",
    }