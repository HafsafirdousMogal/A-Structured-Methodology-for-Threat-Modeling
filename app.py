import streamlit as st
import pandas as pd
import os
from ai_assisted_pasta_pipeline import run_pipeline

# ---------------------------------------------------------
# PAGE CONFIG
# ---------------------------------------------------------
st.set_page_config(
    page_title="AI-Assisted PASTA Tool",
    layout="centered"
)

st.title("AI-Assisted PASTA Threat Modeling Tool")
st.markdown("Automated Risk Analysis and Mitigation using PASTA Methodology")

# ---------------------------------------------------------
# FILE UPLOAD
# ---------------------------------------------------------
uploaded_file = st.file_uploader("Upload threatlist.csv", type=["csv"])

required_columns = {
    "Id",
    "Title",
    "Category",
    "Interaction",
    "Priority",
    "Description"
}

# ---------------------------------------------------------
# MAIN LOGIC
# ---------------------------------------------------------
if uploaded_file:

    df = pd.read_csv(uploaded_file)

    # File Validation
    if not required_columns.issubset(set(df.columns)):
        st.error("Invalid threat model file format. Required columns missing.")
    else:
        st.success("File validated successfully.")

        if st.button("Run PASTA Analysis"):

            # Save uploaded file temporarily
            temp_path = "temp_threatlist.csv"
            df.to_csv(temp_path, index=False)

            # Run pipeline
            result = run_pipeline(temp_path)

            st.success("PASTA Analysis Completed Successfully!")

            # -------------------------------------------------
            # STAGE 4 DISPLAY
            # -------------------------------------------------
            st.subheader("PASTA Stage 4 – Risk Analysis")
            st.dataframe(result["stage4"], use_container_width=True)

            # Risk Distribution Graph
            st.subheader("Risk Distribution")
            risk_counts = result["stage4"]["Risk"].value_counts()
            st.bar_chart(risk_counts)

            # -------------------------------------------------
            # STAGE 5 DISPLAY
            # -------------------------------------------------
            st.subheader("PASTA Stage 5 – Mitigation Strategy")
            st.dataframe(result["stage5"], use_container_width=True)

            # -------------------------------------------------
            # PDF DOWNLOAD
            # -------------------------------------------------
            pdf_path = result["pdf_path"]

            if os.path.exists(pdf_path):
                with open(pdf_path, "rb") as pdf_file:
                    st.download_button(
                        label="Download PASTA Report (PDF)",
                        data=pdf_file,
                        file_name="PASTA_Report.pdf",
                        mime="application/pdf"
                    )

            st.info(f"Outputs saved in: {result['output_dir']}")
