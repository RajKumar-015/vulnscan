import streamlit as st
import tempfile
import os
from detector import detect
from prompt_builder import build_prompt
from patcher import patch_code
from verifier import verify_patch

# ─── Page Config ───────────────────────────────────────────
st.set_page_config(
    page_title="VulnScan — AI Vulnerability Detection & Patching",
    page_icon="🔒",
    layout="wide",
    initial_sidebar_state="collapsed"
)

# ─── Custom CSS Theme ──────────────────────────────────────
st.markdown("""
<style>
    /* Dark Theme Setup */
    .stApp {
        background-color: #0b0f19;
        color: #e2e8f0;
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    }

    /* Container Spacing */
    .block-container {
        padding-top: 2rem;
        padding-bottom: 3rem;
        max-width: 1200px;
    }

    /* Header Styling */
    .vs-header {
        display: flex;
        align-items: center;
        gap: 12px;
        margin-bottom: 6px;
    }
    .vs-logo {
        font-size: 32px;
    }
    .vs-title {
        font-size: 32px;
        font-weight: 800;
        color: #f8fafc;
        letter-spacing: -0.5px;
    }
    .vs-badge {
        background: #1e293b;
        color: #38bdf8;
        border: 1px solid #334155;
        font-size: 11px;
        font-weight: 600;
        padding: 3px 8px;
        border-radius: 12px;
        letter-spacing: 0.5px;
        text-transform: uppercase;
    }
    .vs-subtitle {
        color: #94a3b8;
        font-size: 15px;
        margin-bottom: 1.5rem;
    }

    /* Pipeline Diagram */
    .pipeline-container {
        display: grid;
        grid-template-columns: repeat(5, 1fr);
        gap: 10px;
        margin-bottom: 2rem;
        padding: 14px;
        background: #111827;
        border: 1px solid #1f2937;
        border-radius: 8px;
    }
    .pipeline-step {
        text-align: center;
        padding: 10px 8px;
        background: #1e293b;
        border: 1px solid #334155;
        border-radius: 6px;
    }
    .pipeline-step-num {
        font-size: 10px;
        font-weight: 700;
        color: #38bdf8;
        text-transform: uppercase;
        letter-spacing: 0.5px;
        margin-bottom: 2px;
    }
    .pipeline-step-title {
        font-size: 13px;
        font-weight: 600;
        color: #f1f5f9;
    }
    .pipeline-step-tech {
        font-size: 11px;
        color: #94a3b8;
        margin-top: 2px;
    }

    /* Metric Cards */
    .metric-card {
        background: #111827;
        border: 1px solid #1f2937;
        border-radius: 8px;
        padding: 16px 20px;
        text-align: left;
    }
    .metric-label {
        font-size: 12px;
        font-weight: 600;
        color: #94a3b8;
        text-transform: uppercase;
        letter-spacing: 0.5px;
        margin-bottom: 6px;
    }
    .metric-value {
        font-size: 22px;
        font-weight: 700;
        color: #f8fafc;
    }
    .metric-sub {
        font-size: 12px;
        color: #64748b;
        margin-top: 4px;
    }

    /* Decision Banners */
    .banner-vulnerable {
        background-color: #2a1215;
        border: 1px solid #7f1d1d;
        border-left: 4px solid #ef4444;
        border-radius: 6px;
        padding: 16px;
        margin-top: 1rem;
        margin-bottom: 1.5rem;
    }
    .banner-safe {
        background-color: #062318;
        border: 1px solid #064e3b;
        border-left: 4px solid #10b981;
        border-radius: 6px;
        padding: 16px;
        margin-top: 1rem;
        margin-bottom: 1.5rem;
    }
    .banner-title {
        font-size: 16px;
        font-weight: 700;
        margin-bottom: 4px;
    }
    .banner-desc {
        font-size: 14px;
        color: #cbd5e1;
    }

    /* CWE Pills */
    .cwe-pill {
        display: inline-block;
        background: #374151;
        color: #f3f4f6;
        border: 1px solid #4b5563;
        font-size: 12px;
        font-weight: 600;
        padding: 2px 8px;
        border-radius: 4px;
        margin-right: 6px;
        margin-top: 6px;
    }

    /* Verification Alert Cards */
    .verify-success {
        background: #062318;
        border: 1px solid #064e3b;
        border-left: 4px solid #10b981;
        border-radius: 6px;
        padding: 14px 18px;
        color: #a7f3d0;
        font-weight: 600;
        margin-bottom: 1rem;
    }
    .verify-fail {
        background: #2a1215;
        border: 1px solid #7f1d1d;
        border-left: 4px solid #ef4444;
        border-radius: 6px;
        padding: 14px 18px;
        color: #fca5a5;
        font-weight: 600;
        margin-bottom: 1rem;
    }

    /* Footer */
    .vs-footer {
        margin-top: 4rem;
        padding-top: 1.5rem;
        border-top: 1px solid #1f2937;
        text-align: center;
        color: #64748b;
        font-size: 13px;
    }
</style>
""", unsafe_allow_html=True)

# ─── Header ────────────────────────────────────────────────
st.markdown("""
<div class="vs-header">
    <span class="vs-logo">🔒</span>
    <span class="vs-title">VulnScan</span>
    <span class="vs-badge">v1.0 Security Suite</span>
</div>
<div class="vs-subtitle">
    Automated C/C++ Vulnerability Detection, CWE Classification, AI Patch Generation & Verification
</div>
""", unsafe_allow_html=True)

# ─── Pipeline Visualization ────────────────────────────────
st.markdown("""
<div class="pipeline-container">
    <div class="pipeline-step">
        <div class="pipeline-step-num">Stage 1</div>
        <div class="pipeline-step-title">Source Input</div>
        <div class="pipeline-step-tech">.C / .CPP File</div>
    </div>
    <div class="pipeline-step">
        <div class="pipeline-step-num">Stage 2</div>
        <div class="pipeline-step-title">ML Detection</div>
        <div class="pipeline-step-tech">CodeBERT Classifier</div>
    </div>
    <div class="pipeline-step">
        <div class="pipeline-step-num">Stage 3</div>
        <div class="pipeline-step-title">Static Analysis</div>
        <div class="pipeline-step-tech">Flawfinder + Cppcheck</div>
    </div>
    <div class="pipeline-step">
        <div class="pipeline-step-num">Stage 4</div>
        <div class="pipeline-step-title">AI Patching</div>
        <div class="pipeline-step-tech">Llama 3.2 (3B)</div>
    </div>
    <div class="pipeline-step">
        <div class="pipeline-step-num">Stage 5</div>
        <div class="pipeline-step-title">Remediation Check</div>
        <div class="pipeline-step-tech">Cppcheck Verification</div>
    </div>
</div>
""", unsafe_allow_html=True)

# ─── Load CodeBERT once ────────────────────────────────────
@st.cache_resource
def load_model():
    from transformers import pipeline
    return pipeline(
        "text-classification",
        model="mrm8488/codebert-base-finetuned-detect-insecure-code"
    )

with st.spinner("Initializing CodeBERT detection engine..."):
    classifier = load_model()

# ─── Input Section ─────────────────────────────────────────
st.subheader("📂 Code Inspection Target")

input_method = st.radio(
    "Select input format:",
    ["Upload C/C++ file", "Paste code directly"],
    horizontal=True,
    label_visibility="collapsed"
)

code = ""

if input_method == "Upload C/C++ file":
    uploaded_file = st.file_uploader(
        "Upload source file (.c, .cpp, .h)",
        type=["c", "cpp", "h"]
    )
    if uploaded_file:
        code = uploaded_file.read().decode("utf-8")
        st.markdown("**Source Code Preview:**")
        st.code(code, language="c", line_numbers=True)

else:
    code = st.text_area(
        "Paste C/C++ code for analysis:",
        height=220,
        placeholder="#include <string.h>\nvoid processInput(char *input) {\n    char dest[64];\n    strcpy(dest, input);\n}"
    )

# ─── Action Button ─────────────────────────────────────────
analyze_clicked = st.button(
    "🔍 Analyze & Patch Vulnerabilities",
    type="primary",
    disabled=not code.strip(),
    use_container_width=True
)

if analyze_clicked:

    st.markdown("---")

    # Stage 1 — Detection
    with st.spinner("Executing hybrid detection pipeline (CodeBERT + Flawfinder + Cppcheck)..."):
        detection = detect(code)

    # ─── Metrics Dashboard ───
    st.subheader("📊 Vulnerability Assessment Summary")

    col1, col2, col3, col4 = st.columns(4)

    status_color = "#ef4444" if "VULNERABLE" in detection['decision'] else "#10b981"
    cb_label = detection['codebert']['label']
    cb_score = f"{detection['codebert']['score']*100:.1f}%"

    with col1:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-label">Security Decision</div>
            <div class="metric-value" style="color: {status_color}; font-size: 18px;">{detection['decision']}</div>
            <div class="metric-sub">Confidence: {detection['confidence']}</div>
        </div>
        """, unsafe_allow_html=True)

    with col2:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-label">CodeBERT ML Model</div>
            <div class="metric-value">{cb_label}</div>
            <div class="metric-sub">{cb_score} confidence</div>
        </div>
        """, unsafe_allow_html=True)

    with col3:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-label">Flawfinder Issues</div>
            <div class="metric-value">{len(detection['flawfinder'])}</div>
            <div class="metric-sub">Static pattern triggers</div>
        </div>
        """, unsafe_allow_html=True)

    with col4:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-label">Cppcheck Issues</div>
            <div class="metric-value">{len(detection['cppcheck'])}</div>
            <div class="metric-sub">AST static analysis</div>
        </div>
        """, unsafe_allow_html=True)

    # Decision Banner
    if detection['decision'] == "SAFE":
        st.markdown("""
        <div class="banner-safe">
            <div class="banner-title" style="color: #34d399;">✅ Code Assessed as SAFE</div>
            <div class="banner-desc">No security vulnerabilities or risky buffer patterns detected across static analysis engines.</div>
        </div>
        """, unsafe_allow_html=True)
        st.stop()
    else:
        cwes_html = "".join([f'<span class="cwe-pill">{cwe}</span>' for cwe in detection['cwes']]) if detection['cwes'] else '<span class="cwe-pill">General Vulnerability</span>'
        st.markdown(f"""
        <div class="banner-vulnerable">
            <div class="banner-title" style="color: #f87171;">⚠️ {detection['decision']} (Confidence: {detection['confidence']})</div>
            <div class="banner-desc">Identified Weaknesses: {cwes_html}</div>
        </div>
        """, unsafe_allow_html=True)

    st.markdown("---")

    # Stage 2+3 — Patch
    with st.spinner("🦙 LLaMA 3.2 (3B) generating secure remediation patch..."):
        prompt = build_prompt(code, detection['cwes'], detection['flawfinder'])
        patch = patch_code(prompt)

    # Stage 4 — Verify
    with st.spinner("Running Cppcheck automated patch verification..."):
        verification = verify_patch(patch['patched_code'], detection['cwes'])

    # ─── Detailed Results Tabs ─────────────────────────────
    st.subheader("📋 Remediation & Verification Breakdown")

    tab1, tab2, tab3 = st.tabs(["🔍 Vulnerability Explanation", "🔧 Patched Code & Changes", "✅ Verification Report"])

    with tab1:
        st.markdown("#### Vulnerability Diagnosis")
        # Show explanation; fallback to changes if missing
        explanation_text = patch.get('explanation') or patch.get('changes')
        if explanation_text:
            st.markdown(explanation_text)
        else:
            st.info("No detailed explanation returned by patcher.")

    with tab2:
        col_left, col_right = st.columns(2)
        with col_left:
            st.markdown("#### Original Code")
            st.code(code.strip(), language="c", line_numbers=True)

        with col_right:
            st.markdown("#### Secure Patched Code")
            # Show patched code; fallback to changes if missing
            code_text = patch.get('patched_code') or patch.get('changes')
            if code_text:
                clean_code = code_text.replace("```c", "").replace("```", "").strip()
                st.code(clean_code, language="c", line_numbers=True)
            else:
                st.warning("Patched code block not returned.")

        st.markdown("---")
        st.markdown("#### Summary of Remediation Changes")
        if patch['changes']:
            st.markdown(patch['changes'])
        else:
            st.info(patch.get('full_response', 'No specific changes summary listed.'))

    with tab3:
        st.markdown("#### Automated Verification Engine")
        if "PASSED" in verification['status']:
            st.markdown("""
            <div class="verify-success">
                ✅ Patch Verification PASSED — Identified CWE vulnerabilities resolved successfully.
            </div>
            """, unsafe_allow_html=True)
        else:
            st.markdown("""
            <div class="verify-fail">
                ❌ Patch Verification FAILED — Potential residual vulnerabilities detected.
            </div>
            """, unsafe_allow_html=True)

        if verification['remaining_issues']:
            st.markdown("**Static Analysis Notes & Warnings:**")
            for issue in verification['remaining_issues']:
                st.code(issue, language="text")
        else:
            st.caption("No remaining warnings or issues reported by Cppcheck.")

# ─── Footer ────────────────────────────────────────────────
st.markdown("""
<div class="vs-footer">
    <b>VulnScan</b> — Automated C/C++ Vulnerability Detection & Remediation Engine<br>
    Powered by <b>CodeBERT</b> • <b>Flawfinder</b> • <b>Cppcheck</b> • <b>Llama 3.2 3B</b>
</div>
""", unsafe_allow_html=True)