from detector import detect
from prompt_builder import build_prompt
from patcher import patch_code
from verifier import verify_patch

def run_pipeline(code: str):
    print("\n" + "="*60)
    print("       VULNSCAN — AUTOMATED VULNERABILITY DETECTION")
    print("="*60)

    # Stage 1 — Detection
    detection = detect(code)

    if detection['decision'] == "SAFE":
        print("\n✅ Code is SAFE. No patching needed.")
        return

    # Stage 2 — Build CoT Prompt
    prompt = build_prompt(
        code,
        detection['cwes'],
        detection['flawfinder']
    )

    # Stage 3 — Patch
    patch = patch_code(prompt)

    # Stage 4 — Verify
    verification = verify_patch(
        patch['patched_code'],
        detection['cwes']
    )

    # Final Report
    print("\n" + "="*60)
    print("                    FINAL REPORT")
    print("="*60)
    print(f"\n📌 DECISION     : {detection['decision']}")
    print(f"📌 CONFIDENCE   : {detection['confidence']}")
    print(f"📌 CWE IDs      : {detection['cwes']}")
    print(f"\n📋 EXPLANATION  :\n{patch['explanation']}")
    print(f"\n🔧 PATCHED CODE :\n{patch['patched_code']}")
    print(f"\n📝 CHANGES      :\n{patch['changes']}")
    print(f"\n✅ VERIFICATION : {verification['status']}")
    print("="*60)


if __name__ == "__main__":
    test_code = """
    #include <string.h>
    void processInput(char *input) {
        char dest[64];
        strcpy(dest, input);
    }
    """
    run_pipeline(test_code)