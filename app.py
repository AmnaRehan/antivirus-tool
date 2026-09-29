import streamlit as st
import os

from antivirus import scan_folder, quarantine_file


# -----------------------------
# PAGE CONFIGURATION
# -----------------------------

st.set_page_config(
    page_title="Mini Antivirus",
    page_icon="🛡️",
    layout="wide"
)


# -----------------------------
# CUSTOM CSS
# -----------------------------

st.markdown("""
<style>

.main {
    background-color: #0e1117;
}

.title {
    font-size: 42px;
    font-weight: bold;
}

.subtitle {
    color: #9aa4b2;
    font-size: 18px;
}

.card {
    padding: 20px;
    border-radius: 12px;
    background-color: #1a1f29;
    text-align: center;
}

.safe {
    color: #21c55d;
    font-weight: bold;
}

.warning {
    color: #f59e0b;
    font-weight: bold;
}

.danger {
    color: #ef4444;
    font-weight: bold;
}

</style>
""", unsafe_allow_html=True)


# -----------------------------
# HEADER
# -----------------------------

st.markdown(
    '<div class="title">🛡️ Mini Antivirus</div>',
    unsafe_allow_html=True
)

st.markdown(
    '<div class="subtitle">'
    'Scan your files for potentially suspicious activity'
    '</div>',
    unsafe_allow_html=True
)

st.divider()


# -----------------------------
# FOLDER INPUT
# -----------------------------

st.subheader("📁 Select Folder")

folder = st.text_input(
    "Enter the folder path you want to scan:",
    placeholder=r"C:\Users\YourName\Desktop\test_folder"
)


# -----------------------------
# SCAN BUTTON
# -----------------------------

if st.button("🔍 Start Scan", use_container_width=True):

    if not folder:

        st.error("Please enter a folder path.")

    elif not os.path.isdir(folder):

        st.error("The folder does not exist.")

    else:

        with st.spinner("Scanning files..."):

            results = scan_folder(folder)

        st.session_state["results"] = results


# -----------------------------
# DISPLAY RESULTS
# -----------------------------

if "results" in st.session_state:

    results = st.session_state["results"]

    total_files = len(results)

    threats = [
        r for r in results
        if r["status"] != "SAFE"
    ]

    safe_files = [
        r for r in results
        if r["status"] == "SAFE"
    ]


    # -------------------------
    # STATISTICS
    # -------------------------

    st.subheader("📊 Scan Summary")

    col1, col2, col3 = st.columns(3)

    with col1:

        st.metric(
            "Files Scanned",
            total_files
        )

    with col2:

        st.metric(
            "Safe Files",
            len(safe_files)
        )

    with col3:

        st.metric(
            "Threats Found",
            len(threats)
        )


    st.divider()


    # -------------------------
    # THREAT MESSAGE
    # -------------------------

    if len(threats) == 0:

        st.success(
            "✅ No suspicious files were detected."
        )

    else:

        st.warning(
            f"⚠️ {len(threats)} suspicious file(s) detected."
        )


    # -------------------------
    # RESULTS
    # -------------------------

    st.subheader("🔎 Scan Results")


    for index, result in enumerate(results):

        filename = os.path.basename(
            result["file"]
        )

        status = result["status"]

        score = result["score"]


        if status == "SAFE":

            st.success(
                f"✓ {filename} — SAFE"
            )

        elif status == "SUSPICIOUS":

            with st.expander(
                f"⚠️ {filename} — SUSPICIOUS"
            ):

                st.write(
                    f"**Risk Score:** {score}"
                )

                st.write("**Reasons:**")

                for threat in result["threats"]:

                    st.write(
                        f"• {threat}"
                    )


                if st.button(
                    "🗑️ Quarantine",
                    key=f"quarantine_{index}"
                ):

                    try:

                        new_path = quarantine_file(
                            result["file"]
                        )

                        st.success(
                            f"File moved to quarantine: {new_path}"
                        )

                    except Exception as e:

                        st.error(
                            f"Error: {e}"
                        )

        else:

            with st.expander(
                f"🚨 {filename} — MALICIOUS"
            ):

                st.error(
                    f"Risk Score: {score}"
                )

                st.write("**Reasons:**")

                for threat in result["threats"]:

                    st.write(
                        f"• {threat}"
                    )

                if st.button(
                    "🗑️ Quarantine",
                    key=f"malicious_{index}"
                ):

                    try:

                        new_path = quarantine_file(
                            result["file"]
                        )

                        st.success(
                            "File quarantined successfully."
                        )

                    except Exception as e:

                        st.error(
                            f"Error: {e}"
                        )