import json
import sys

import streamlit as st


# --------------------------------------------------
# Import backend
# --------------------------------------------------

sys.path.append("src")

from ai_assistant import run_security_analysis
from log_reader import load_logs


# --------------------------------------------------
# Page configuration
# --------------------------------------------------

st.set_page_config(
    page_title="AI Security Assistant",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)


# --------------------------------------------------
# Custom styling
# --------------------------------------------------

st.markdown(
    """
    <style>

    /* ==============================
       Global
       ============================== */

    .stApp {
        background-color: #f5f7fa;
        color: #172033;
    }

    .block-container {
        padding-top: 2rem;
        padding-bottom: 3rem;
        max-width: 1450px;
    }


    /* ==============================
       Sidebar
       ============================== */

    section[data-testid="stSidebar"] {
        background-color: #ffffff;
        border-right: 1px solid #e1e5eb;
    }


    /* ==============================
       Headings
       ============================== */

    h1 {
        color: #172033 !important;
        font-weight: 700 !important;
    }

    h2 {
        color: #172033 !important;
        font-weight: 650 !important;
    }

    h3 {
        color: #263247 !important;
    }


    /* ==============================
       Main text
       ============================== */

    p {
        color: #374151;
    }


    /* ==============================
       Metric cards
       ============================== */

    div[data-testid="stMetric"] {
        background-color: #ffffff;
        border: 1px solid #e1e5eb;
        border-radius: 12px;
        padding: 1rem;
        box-shadow: 0 2px 6px rgba(0, 0, 0, 0.04);
    }

    div[data-testid="stMetricLabel"] {
        color: #667085 !important;
    }

    div[data-testid="stMetricValue"] {
        color: #172033 !important;
        font-weight: 700;
    }


    /* ==============================
       Expanders
       ============================== */

    div[data-testid="stExpander"] {
        background-color: #ffffff;
        border: 1px solid #e1e5eb;
        border-radius: 10px;
        margin-bottom: 0.8rem;
    }


    /* ==============================
       Select box
       ============================== */

    div[data-baseweb="select"] > div {
        background-color: #ffffff;
        border-color: #d5dbe3;
    }


    /* ==============================
       File uploader
       ============================== */

    section[data-testid="stFileUploaderDropzone"] {
        background-color: #ffffff;
        border: 1px dashed #c8d0da;
        border-radius: 10px;
    }


    /* ==============================
       Buttons
       ============================== */

    .stButton > button {
        border-radius: 8px;
        font-weight: 600;
    }


    /* ==============================
       Divider
       ============================== */

    hr {
        border-color: #e1e5eb;
    }


    </style>
    """,
    unsafe_allow_html=True,
)


# --------------------------------------------------
# Initialize session state
# --------------------------------------------------

if "analysis_results" not in st.session_state:

    st.session_state.analysis_results = None


if "log_source" not in st.session_state:

    st.session_state.log_source = "Sample Logs"


# --------------------------------------------------
# Header
# --------------------------------------------------

header_col1, header_col2 = st.columns([5, 1])


with header_col1:

    st.title("🛡️ AI Security Assistant")

    st.caption(
        "AI-powered security monitoring and incident analysis"
    )


with header_col2:

    st.success("● SYSTEM ONLINE")


# --------------------------------------------------
# Sidebar
# --------------------------------------------------

with st.sidebar:

    st.markdown("## 🛡️ Security Console")

    st.divider()


    # --------------------------------------------------
    # System status
    # --------------------------------------------------

    st.markdown("### System")

    st.success("Detection Engine Online")
    st.success("MITRE Validator Online")
    st.success("Bedrock AI Online")

    st.divider()


    # --------------------------------------------------
    # Log Source
    # --------------------------------------------------

    st.markdown("### Log Source")


    log_source = st.radio(
        "Choose log source",
        [
            "Sample Logs",
            "Upload Logs",
        ],
        index=0,
        key="log_source",
        label_visibility="collapsed",
    )


    uploaded_file = None


    if log_source == "Upload Logs":

        uploaded_file = st.file_uploader(
            "Upload security log file",
            type=["json"],
            help="Upload a JSON file containing security logs.",
        )


    st.divider()


    # --------------------------------------------------
    # Analysis
    # --------------------------------------------------

    st.markdown("### Analysis")


    analyze_clicked = st.button(
        "🔍 Analyze Logs",
        use_container_width=True,
        type="primary",
    )


    st.divider()


    st.caption("AI Security Assistant")
    st.caption("SOC Monitoring Dashboard")


# --------------------------------------------------
# Load / Analyze logs
# --------------------------------------------------

if analyze_clicked:

    # ----------------------------------------------
    # Sample Logs
    # ----------------------------------------------

    if log_source == "Sample Logs":

        with st.spinner(
            "Analyzing sample security logs..."
        ):

            results = run_security_analysis()


        st.session_state.analysis_results = results


        st.success(
            "Sample logs analyzed successfully."
        )


    # ----------------------------------------------
    # Uploaded Logs
    # ----------------------------------------------

    elif log_source == "Upload Logs":

        if uploaded_file is None:

            st.warning(
                "Please upload a JSON log file before "
                "starting the analysis."
            )

        else:

            try:

                uploaded_data = json.load(
                    uploaded_file
                )


                # ----------------------------------
                # Validate basic structure
                # ----------------------------------

                if not isinstance(
                    uploaded_data,
                    list,
                ):

                    st.error(
                        "Invalid log format. "
                        "The JSON file must contain "
                        "a list of log records."
                    )

                elif len(uploaded_data) == 0:

                    st.error(
                        "The uploaded log file is empty."
                    )

                else:

                    with st.spinner(
                        "Analyzing uploaded security logs..."
                    ):

                        results = run_security_analysis(
                            logs=uploaded_data
                        )


                    st.session_state.analysis_results = (
                        results
                    )


                    st.success(
                        f"Successfully analyzed "
                        f"{len(uploaded_data)} log records."
                    )


            except json.JSONDecodeError:

                st.error(
                    "The uploaded file is not valid JSON."
                )

            except Exception as error:

                st.error(
                    f"Unable to analyze the uploaded "
                    f"log file: {error}"
                )


# --------------------------------------------------
# Get current results
# --------------------------------------------------

results = st.session_state.analysis_results


# --------------------------------------------------
# If no analysis has been run
# --------------------------------------------------

if results is None:

    st.info(
        "Select a log source from the sidebar "
        "and click 'Analyze Logs' to begin."
    )

    st.stop()


# --------------------------------------------------
# Extract results
# --------------------------------------------------

alerts = results["alerts"]

incidents = results["incidents"]

analyses = results["analyses"]


# --------------------------------------------------
# Calculate metrics
# --------------------------------------------------

critical_count = sum(
    1
    for incident in incidents
    if incident["severity"] == "CRITICAL"
)


high_count = sum(
    1
    for incident in incidents
    if incident["severity"] == "HIGH"
)


medium_count = sum(
    1
    for incident in incidents
    if incident["severity"] == "MEDIUM"
)


# --------------------------------------------------
# Security Overview
# --------------------------------------------------

st.markdown("## Security Overview")


metric1, metric2, metric3, metric4 = st.columns(4)


with metric1:

    st.metric(
        "Total Alerts",
        len(alerts),
    )


with metric2:

    st.metric(
        "Incidents",
        len(incidents),
    )


with metric3:

    st.metric(
        "Critical",
        critical_count,
    )


with metric4:

    st.metric(
        "High",
        high_count,
    )


# --------------------------------------------------
# Security Incidents
# --------------------------------------------------

st.markdown("## Security Incidents")


if analyses:

    card_columns = st.columns(
        min(len(analyses), 2)
    )


    for index, item in enumerate(analyses):

        incident = item["incident"]

        severity = incident["severity"]


        with card_columns[index % 2]:

            if severity == "CRITICAL":

                st.error(
                    f"🔴 {severity} — "
                    f"{incident['incident_type']}"
                )

            elif severity == "HIGH":

                st.warning(
                    f"🟠 {severity} — "
                    f"{incident['incident_type']}"
                )

            else:

                st.info(
                    f"🔵 {severity} — "
                    f"{incident['incident_type']}"
                )


            st.markdown(
                f"### Risk Score: "
                f"{incident['risk_score']} / 100"
            )


            st.markdown(
                f"**User:** `{incident['user']}`"
            )


            st.markdown(
                f"**Source IP:** `{incident['source_ip']}`"
            )


            st.divider()


else:

    st.success(
        "No security incidents detected."
    )


# --------------------------------------------------
# Incident Analysis
# --------------------------------------------------

st.markdown("## Incident Analysis")


incident_names = [
    item["incident"]["incident_type"]
    for item in analyses
]


if not incident_names:

    st.success(
        "No incidents available for analysis."
    )

    st.stop()


selected_incident = st.selectbox(
    "Select an incident to investigate",
    incident_names,
)


selected_index = incident_names.index(
    selected_incident
)


selected_item = analyses[selected_index]


incident = selected_item["incident"]

analysis = selected_item["analysis"]


# --------------------------------------------------
# Selected Incident
# --------------------------------------------------

severity = incident["severity"]


if severity == "CRITICAL":

    st.error(
        f"🔴 {severity} — "
        f"{incident['incident_type']}"
    )

elif severity == "HIGH":

    st.warning(
        f"🟠 {severity} — "
        f"{incident['incident_type']}"
    )

else:

    st.info(
        f"🔵 {severity} — "
        f"{incident['incident_type']}"
    )


# --------------------------------------------------
# Incident Details
# --------------------------------------------------

detail1, detail2, detail3, detail4 = st.columns(4)


with detail1:

    st.metric(
        "Risk Score",
        incident["risk_score"],
    )


with detail2:

    st.metric(
        "User",
        incident["user"],
    )


with detail3:

    st.metric(
        "Source IP",
        incident["source_ip"],
    )


with detail4:

    st.metric(
        "Severity",
        incident["severity"],
    )


# --------------------------------------------------
# Risk Score
# --------------------------------------------------

st.markdown("### Risk Level")


risk_score = incident["risk_score"]


st.progress(
    min(risk_score / 100, 1.0)
)


# --------------------------------------------------
# AI Summary
# --------------------------------------------------

st.markdown("### 🤖 AI Summary")


st.info(
    analysis["summary"]
)


# --------------------------------------------------
# Observed Evidence
# --------------------------------------------------

with st.expander(
    "🔎 Observed Evidence",
    expanded=True,
):

    evidence_items = analysis.get(
        "observed_evidence",
        []
    )


    valid_evidence = [
        item
        for item in evidence_items
        if isinstance(item, str)
        and item.strip()
    ]


    if valid_evidence:

        for evidence in valid_evidence:

            st.markdown(
                f"- {evidence}"
            )

    else:

        st.info(
            "No observed evidence was returned."
        )


# --------------------------------------------------
# Security Assessment
# --------------------------------------------------

with st.expander(
    "🧠 Security Assessment",
    expanded=True,
):

    assessment_items = analysis.get(
        "assessment",
        []
    )


    valid_assessment = [
        item
        for item in assessment_items
        if isinstance(item, str)
        and item.strip()
    ]


    if valid_assessment:

        for assessment in valid_assessment:

            st.markdown(
                f"- {assessment}"
            )

    else:

        st.info(
            "No security assessment was returned."
        )


# --------------------------------------------------
# Recommended Investigation
# --------------------------------------------------

with st.expander(
    "🔍 Recommended Investigation",
):

    recommendations = analysis.get(
        "recommended_investigation",
        []
    )


    valid_recommendations = [
        item
        for item in recommendations
        if isinstance(item, str)
        and item.strip()
    ]


    if valid_recommendations:

        for recommendation in valid_recommendations:

            st.markdown(
                f"- {recommendation}"
            )

    else:

        st.info(
            "No investigation steps were returned by the AI."
        )


# --------------------------------------------------
# Recommended Remediation
# --------------------------------------------------

with st.expander(
    "🛠️ Recommended Remediation",
):

    remediations = analysis.get(
        "recommended_remediation",
        []
    )


    valid_remediations = [
        item
        for item in remediations
        if isinstance(item, str)
        and item.strip()
    ]


    if valid_remediations:

        for remediation in valid_remediations:

            st.markdown(
                f"- {remediation}"
            )

    else:

        st.info(
            "No remediation actions were returned by the AI."
        )


# --------------------------------------------------
# MITRE ATT&CK
# --------------------------------------------------

st.markdown("### 🎯 MITRE ATT&CK")


mitre_attack = analysis.get(
    "mitre_attack",
    []
)


if mitre_attack:

    for technique in mitre_attack:

        technique_id = technique.get(
            "technique_id",
            "Unknown"
        )

        technique_name = technique.get(
            "technique_name",
            "Unknown"
        )

        reason = technique.get(
            "reason",
            ""
        )


        st.info(
            f"**{technique_id} — "
            f"{technique_name}**\n\n"
            f"{reason}"
        )


else:

    st.info(
        "No MITRE ATT&CK technique was "
        "identified from the available evidence."
    )


# --------------------------------------------------
# AI Confidence
# --------------------------------------------------

st.markdown("### 📊 AI Confidence")


confidence = analysis.get(
    "confidence",
    "low"
)


if confidence == "high":

    st.success(
        "🟢 HIGH confidence"
    )

elif confidence == "medium":

    st.warning(
        "🟡 MEDIUM confidence"
    )

else:

    st.info(
        "🔵 LOW confidence"
    )


# --------------------------------------------------
# Footer
# --------------------------------------------------

st.divider()


st.caption(
    "AI Security Assistant • "
    "Detection Engine + MITRE Validation + "
    "Amazon Bedrock"
)

