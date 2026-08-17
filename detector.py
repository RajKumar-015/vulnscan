import subprocess
import re
import os
from transformers import pipeline

TEMP_FILE = os.path.join(os.path.dirname(__file__), "temp_code.c")

classifier = None


def load_classifier():
    global classifier
    if classifier is None:
        print("Loading CodeBERT model...")
        classifier = pipeline(
            "text-classification",
            model="mrm8488/codebert-base-finetuned-detect-insecure-code"
        )
        print("CodeBERT loaded ✅")
    return classifier


def run_flawfinder(code: str) -> tuple:
    with open(TEMP_FILE, "w", encoding="utf-8") as f:
        f.write(code)

    result = subprocess.run(
        ["flawfinder", "--dataonly", "--quiet", TEMP_FILE],
        capture_output=True,
        text=True
    )

    findings = []
    cwes = []

    for line in result.stdout.splitlines():
        line = line.strip()
        if not line:
            continue

        if ":" in line:
            findings.append(line)

        matches = re.findall(r"CWE-\d+", line, re.IGNORECASE)
        cwes.extend(m.upper() for m in matches)

    return findings, sorted(set(cwes))


def run_cppcheck(code: str) -> tuple:
    with open(TEMP_FILE, "w", encoding="utf-8") as f:
        f.write(code)

    result = subprocess.run(
        [
            "cppcheck",
            "--enable=all",
            "--template={file}:{line}:{severity}:{id}:{message}",
            TEMP_FILE
        ],
        capture_output=True,
        text=True
    )

    findings = []
    cwes = []

    for line in result.stderr.splitlines():
        line = line.strip()
        if not line:
            continue

        findings.append(line)

        # Only map findings that correspond to a security weakness.
        # Generic Cppcheck warnings/info messages must NOT make a program
        # "confirmed vulnerable".
        lower = line.lower()

        if "bufferaccessoutofbounds" in lower or "bufferoverflow" in lower:
            cwes.append("CWE-120")

        if "memleak" in lower:
            cwes.append("CWE-401")

        if "useafterfree" in lower or "deallocuse" in lower:
            cwes.append("CWE-416")

        if "nullpointer" in lower:
            cwes.append("CWE-476")

        if "uninitvar" in lower:
            cwes.append("CWE-457")

        if "strcpy" in lower or "strcat" in lower:
            cwes.append("CWE-120")

        if "arrayindexoutofbounds" in lower:
            cwes.append("CWE-787")

    return findings, sorted(set(cwes))


def run_codebert(code: str) -> dict:
    clf = load_classifier()

    # The current model is a sequence-classification model. Keep the same
    # input behavior as before, but expose the score clearly.
    result = clf(code[:512])

    label = result[0]["label"]
    score = result[0]["score"]

    if label == "LABEL_1":
        label = "VULNERABLE"
    elif label == "LABEL_0":
        label = "SAFE"

    return {
        "label": label,
        "score": round(score, 4)
    }


def hybrid_decision(codebert_result, security_cwes):
    """
    Hybrid decision policy.

    IMPORTANT:
    A generic Cppcheck/Flawfinder finding is NOT enough to confirm a
    vulnerability. Static confirmation requires mapped security CWE evidence.

    This preserves CodeBERT as an independent detector:
      ML + static CWE  -> CONFIRMED VULNERABLE
      ML only          -> ML-SUSPECTED
      static CWE only  -> CONFIRMED VULNERABLE
      neither          -> SAFE
    """
    codebert_vuln = codebert_result["label"] == "VULNERABLE"
    static_security_vuln = len(security_cwes) > 0

    if codebert_vuln and static_security_vuln:
        return {
            "decision": "CONFIRMED VULNERABLE",
            "confidence": "HIGH",
            "decision_reason": (
                "CodeBERT detected a vulnerability and static analysis "
                "provided mapped security CWE evidence."
            )
        }

    if codebert_vuln and not static_security_vuln:
        return {
            "decision": "ML-SUSPECTED",
            "confidence": "MEDIUM",
            "decision_reason": (
                "CodeBERT detected potentially insecure code, but static "
                "analysis did not provide mapped security CWE evidence. "
                "Secondary validation is required before remediation."
            )
        }

    if not codebert_vuln and static_security_vuln:
        return {
            "decision": "CONFIRMED VULNERABLE",
            "confidence": "MEDIUM",
            "decision_reason": (
                "Static analysis identified mapped security CWE evidence "
                "even though CodeBERT did not flag the source."
            )
        }

    return {
        "decision": "SAFE",
        "confidence": "HIGH",
        "decision_reason": (
            "Neither CodeBERT nor static analysis identified a confirmed "
            "security weakness."
        )
    }


def detect(code: str) -> dict:
    print("\n🔍 Running detection...\n")

    codebert_result = run_codebert(code)
    flawfinder_findings, flawfinder_cwes = run_flawfinder(code)
    cppcheck_findings, cppcheck_cwes = run_cppcheck(code)

    cwes = sorted(set(flawfinder_cwes + cppcheck_cwes))

    decision = hybrid_decision(codebert_result, cwes)

    result = {
        "codebert": codebert_result,
        "flawfinder": flawfinder_findings,
        "cppcheck": cppcheck_findings,
        "cwes": cwes,
        "decision": decision["decision"],
        "confidence": decision["confidence"],
        "decision_reason": decision["decision_reason"]
    }

    print(f"CodeBERT     : {codebert_result['label']} ({codebert_result['score']})")
    print(f"Flawfinder   : {len(flawfinder_findings)} findings")
    print(f"Cppcheck     : {len(cppcheck_findings)} findings")
    print(f"Security CWEs: {cwes if cwes else 'None found'}")
    print(f"Decision     : {decision['decision']}")
    print(f"Confidence   : {decision['confidence']}")

    return result