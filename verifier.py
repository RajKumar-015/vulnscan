import os
import re
import subprocess
import shutil

TEMP_PATCHED = os.path.join(os.path.dirname(__file__), "temp_patched.c")

# Verification patterns correspond to evidence emitted by the analyzers,
# not merely the presence of a function name in the source.
CWE_PATTERNS = {
    "CWE-120": [
        r"bufferAccessOutOfBounds",
        r"bufferOverflow",
        r"buffer overflow",
        r"gets\b",
        r"strcpy\b",
        r"strcat\b",
        r"sprintf\b",
    ],
    "CWE-401": [r"memleak"],
    "CWE-416": [r"useafterfree", r"deallocuse"],
    "CWE-476": [r"nullPointer"],
    "CWE-457": [r"uninitvar"],
}



def _compile_check(code: str):
    """
    Validate that the generated C/C++ source is syntactically/type-correct
    before trusting static-analysis results.

    Returns:
        {
            "status": "PASSED" | "FAILED" | "UNAVAILABLE",
            "compiler": str | None,
            "diagnostics": list[str]
        }
    """
    c_path = os.path.join(os.path.dirname(__file__), "temp_patched.c")
    cpp_path = os.path.join(os.path.dirname(__file__), "temp_patched.cpp")

    # Try C first. This is the normal path for VulnScan's C samples.
    gcc = shutil.which("gcc")
    if gcc:
        with open(c_path, "w", encoding="utf-8") as f:
            f.write(code)

        result = subprocess.run(
            [gcc, "-std=c11", "-fsyntax-only", c_path],
            capture_output=True,
            text=True,
        )
        if result.returncode == 0:
            return {
                "status": "PASSED",
                "compiler": "gcc",
                "diagnostics": [],
            }

        c_diagnostics = [
            line.strip()
            for line in (result.stderr or "").splitlines()
            if line.strip()
        ]
    else:
        c_diagnostics = []

    # If C compilation fails, also try C++ so .cpp/header-style code can be
    # verified without incorrectly rejecting valid C++ syntax.
    gpp = shutil.which("g++")
    if gpp:
        with open(cpp_path, "w", encoding="utf-8") as f:
            f.write(code)

        result = subprocess.run(
            [gpp, "-std=c++17", "-fsyntax-only", cpp_path],
            capture_output=True,
            text=True,
        )
        if result.returncode == 0:
            return {
                "status": "PASSED",
                "compiler": "g++",
                "diagnostics": [],
            }

        cpp_diagnostics = [
            line.strip()
            for line in (result.stderr or "").splitlines()
            if line.strip()
        ]
    else:
        cpp_diagnostics = []

    if gcc is None and gpp is None:
        return {
            "status": "UNAVAILABLE",
            "compiler": None,
            "diagnostics": [
                "No C/C++ compiler (gcc or g++) is available in this environment."
            ],
        }

    diagnostics = c_diagnostics + cpp_diagnostics
    return {
        "status": "FAILED",
        "compiler": "gcc/g++",
        "diagnostics": list(dict.fromkeys(diagnostics)),
    }


def _run_static_analysis(code: str):
    with open(TEMP_PATCHED, "w", encoding="utf-8") as f:
        f.write(code)

    cppcheck = subprocess.run(
        [
            "cppcheck",
            "--enable=all",
            "--inconclusive",
            "--template={file}:{line}:{severity}:{id}:{message}",
            TEMP_PATCHED,
        ],
        capture_output=True,
        text=True,
    )

    flawfinder = subprocess.run(
        ["flawfinder", "--dataonly", "--quiet", TEMP_PATCHED],
        capture_output=True,
        text=True,
    )

    cppcheck_findings = [
        line.strip()
        for line in cppcheck.stderr.splitlines()
        if line.strip() and "information" not in line.lower()
    ]
    flawfinder_findings = [
        line.strip()
        for line in flawfinder.stdout.splitlines()
        if line.strip() and ":" in line
    ]
    return cppcheck_findings, flawfinder_findings


def _remaining_cwes(original_cwes, cppcheck_findings, flawfinder_findings):
    all_findings = cppcheck_findings + flawfinder_findings
    remaining = []
    for cwe in original_cwes:
        patterns = CWE_PATTERNS.get(cwe)
        if not patterns:
            # We cannot prove an unknown CWE is fixed with this verifier.
            remaining.append(cwe)
            continue
        if any(
            re.search(pattern, finding, re.IGNORECASE)
            for finding in all_findings
            for pattern in patterns
        ):
            remaining.append(cwe)
    return list(dict.fromkeys(remaining))


def verify_patch(patched_code: str, original_cwes: list) -> dict:
    print("\n🔍 Verifying patch with Cppcheck + Flawfinder...\n")

    cleaned = re.sub(r"^\s*```(?:c|cpp|c\+\+)?\s*", "", patched_code, flags=re.I)
    cleaned = re.sub(r"\s*```\s*$", "", cleaned).strip()

    if not cleaned:
        return {
            "status": "SKIPPED",
            "remaining_issues": [],
            "remaining_cwes": list(original_cwes),
            "feedback": "No patched source code was generated.",
        }

    # Gate the security verification with a compiler/syntax check first.
    # A patch that does not compile is never considered a successful patch,
    # even if Cppcheck happens to report no mapped CWE.
    try:
        compile_result = _compile_check(cleaned)
    except Exception as exc:
        return {
            "status": "UNAVAILABLE",
            "remaining_issues": [],
            "remaining_cwes": list(original_cwes),
            "compiler": None,
            "feedback": f"Compilation/syntax validation could not be completed: {exc}",
        }

    if compile_result["status"] == "UNAVAILABLE":
        return {
            "status": "UNAVAILABLE",
            "remaining_issues": compile_result["diagnostics"],
            "remaining_cwes": list(original_cwes),
            "compiler": None,
            "feedback": compile_result["diagnostics"][0],
        }

    if compile_result["status"] == "FAILED":
        diagnostics = compile_result["diagnostics"] or ["Compiler rejected the generated patch."]
        return {
            "status": "COMPILATION_FAILED",
            "remaining_issues": diagnostics,
            "remaining_cwes": list(original_cwes),
            "compiler": compile_result["compiler"],
            "feedback": (
                "The generated patch failed C/C++ syntax/type validation. "
                "Fix the compiler errors before addressing anything else. "
                "Do not change unrelated program behavior."
            ),
        }

    try:
        cppcheck_findings, flawfinder_findings = _run_static_analysis(cleaned)
    except FileNotFoundError as exc:
        return {
            "status": "UNAVAILABLE",
            "remaining_issues": [],
            "remaining_cwes": list(original_cwes),
            "feedback": f"Required static-analysis tool is unavailable: {exc.filename}",
        }
    except Exception as exc:
        return {
            "status": "UNAVAILABLE",
            "remaining_issues": [],
            "remaining_cwes": list(original_cwes),
            "feedback": f"Patch verification could not be completed: {exc}",
        }

    remaining_cwes = _remaining_cwes(original_cwes, cppcheck_findings, flawfinder_findings)

    relevant = []
    all_findings = cppcheck_findings + flawfinder_findings
    for finding in all_findings:
        for cwe in original_cwes:
            for pattern in CWE_PATTERNS.get(cwe, []):
                if re.search(pattern, finding, re.IGNORECASE):
                    relevant.append(finding)
                    break
            else:
                continue
            break

    if remaining_cwes:
        status = "FAILED ❌"
        feedback = (
            "Static analysis still reports evidence related to "
            + ", ".join(remaining_cwes)
            + ". Fix the identified weakness without changing unrelated behavior."
        )
    else:
        status = "PASSED ✅"
        feedback = "No mapped evidence for the originally identified CWE(s) remains."

    return {
        "status": status,
        "remaining_issues": list(dict.fromkeys(relevant)),
        "remaining_cwes": remaining_cwes,
        "compiler": compile_result["compiler"],
        "feedback": feedback,
    }