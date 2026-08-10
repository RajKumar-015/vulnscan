import subprocess
import os

TEMP_PATCHED = os.path.join(os.path.dirname(__file__), "temp_patched.c")

def verify_patch(patched_code: str, original_cwes: list) -> dict:
    print("\n🔍 Verifying patch with cppcheck...\n")

    # strip markdown code fences
    patched_code = patched_code.replace("```c", "").replace("```", "").strip()

    with open(TEMP_PATCHED, "w") as f:
        f.write(patched_code)

    result = subprocess.run(
        ["cppcheck", "--enable=all",
         "--template={file}:{line}:{severity}:{id}:{message}",
         TEMP_PATCHED],
        capture_output=True, text=True
    )

    findings = []
    for line in result.stderr.splitlines():
        line = line.strip()
        if line and "information" not in line:
            findings.append(line)

    remaining_cwes = []
    for cwe in original_cwes:
        if cwe == "CWE-120" and any("strcpy" in f for f in findings):
            remaining_cwes.append(cwe)

    status = "PASSED ✅" if len(remaining_cwes) == 0 else "FAILED ❌"

    print(f"Verification : {status}")
    print(f"Remaining issues : {findings if findings else 'None'}")

    return {
        "status": status,
        "remaining_issues": findings,
        "remaining_cwes": remaining_cwes
    }