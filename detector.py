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
    with open(TEMP_FILE, "w") as f:
        f.write(code)

    result = subprocess.run(
        ["flawfinder", "--dataonly", "--quiet", TEMP_FILE],
        capture_output=True, text=True
    )

    findings = []
    cwes = []

    for line in result.stdout.splitlines():
        if ":" in line:
            findings.append(line.strip())
        matches = re.findall(r'CWE-\d+', line)
        cwes.extend(matches)

    return findings, list(set(cwes))

def run_cppcheck(code: str) -> tuple:
    with open(TEMP_FILE, "w") as f:
        f.write(code)

    result = subprocess.run(
        ["cppcheck", "--enable=all",
         "--template={file}:{line}:{severity}:{id}:{message}",
         TEMP_FILE],
        capture_output=True, text=True
    )

    findings = []
    cwes = []

    for line in result.stderr.splitlines():
        line = line.strip()
        if line:
            findings.append(line)
            if "bufferAccessOutOfBounds" in line or "bufferOverflow" in line:
                cwes.append("CWE-120")
            if "memleak" in line:
                cwes.append("CWE-401")
            if "useafterfree" in line or "deallocuse" in line:
                cwes.append("CWE-416")
            if "nullPointer" in line:
                cwes.append("CWE-476")
            if "uninitvar" in line:
                cwes.append("CWE-457")
            if "strcpy" in line or "strcat" in line:
                cwes.append("CWE-120")

    return findings, list(set(cwes))

def run_codebert(code: str) -> dict:
    clf = load_classifier()
    result = clf(code[:512])
    label = result[0]['label']
    score = result[0]['score']
    if label == "LABEL_1":
        label = "VULNERABLE"
    elif label == "LABEL_0":
        label = "SAFE"
    return {"label": label, "score": round(score, 4)}

def hybrid_decision(codebert_result, cppcheck_findings, flawfinder_findings):
    codebert_vuln = codebert_result['label'] == 'VULNERABLE'
    static_vuln = len(cppcheck_findings) > 0 or len(flawfinder_findings) > 0

    if codebert_vuln and static_vuln:
        decision = "CONFIRMED VULNERABLE"
        confidence = "HIGH"
    elif codebert_vuln and not static_vuln:
        decision = "POSSIBLY VULNERABLE"
        confidence = "MEDIUM"
    elif not codebert_vuln and static_vuln:
        decision = "CONFIRMED VULNERABLE"
        confidence = "MEDIUM"
    else:
        decision = "SAFE"
        confidence = "HIGH"

    return {"decision": decision, "confidence": confidence}

def detect(code: str) -> dict:
    print("\n🔍 Running detection...\n")

    codebert_result = run_codebert(code)
    flawfinder_findings, flawfinder_cwes = run_flawfinder(code)
    cppcheck_findings, cppcheck_cwes = run_cppcheck(code)
    cwes = list(set(flawfinder_cwes + cppcheck_cwes))

    decision = hybrid_decision(codebert_result, cppcheck_findings, flawfinder_findings)

    result = {
        "codebert": codebert_result,
        "flawfinder": flawfinder_findings,
        "cppcheck": cppcheck_findings,
        "cwes": cwes,
        "decision": decision['decision'],
        "confidence": decision['confidence']
    }

    print(f"CodeBERT     : {codebert_result['label']} ({codebert_result['score']})")
    print(f"Flawfinder   : {len(flawfinder_findings)} findings")
    print(f"Cppcheck     : {len(cppcheck_findings)} findings")
    print(f"CWE IDs      : {cwes if cwes else 'None found'}")
    print(f"Decision     : {decision['decision']}")
    print(f"Confidence   : {decision['confidence']}")

    return result