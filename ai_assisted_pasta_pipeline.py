import pandas as pd
import os
import shutil
from datetime import datetime

from reportlab.platypus import (
    SimpleDocTemplate,
    Table,
    TableStyle,
    Paragraph,
    Spacer,
    PageBreak
)
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors


# =========================================================
# CREATE OUTPUT DIRECTORY
# =========================================================
def create_output_dir():
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    output_dir = f"outputs/run_{timestamp}"
    os.makedirs(output_dir, exist_ok=True)
    print(f"[INFO] Output directory created: {output_dir}")
    return output_dir


# =========================================================
# STEP 1: PREPROCESS THREATS
# =========================================================
def preprocess_threats(input_file, output_dir):
    print("[STEP 1] Pre-processing threat list...")

    df = pd.read_csv(input_file)

    required_columns = ["Id", "Title", "Category", "Interaction", "Priority", "Description"]

    clean_df = df[required_columns].copy()

    clean_path = f"{output_dir}/clean_threats.csv"
    clean_df.to_csv(clean_path, index=False)

    print("[OK] clean_threats.csv created")
    return clean_df


# =========================================================
# AI RISK SCORING (STAGE 4)
# =========================================================
def ai_risk_scoring(row):
    interaction = row["Interaction"]
    category = row["Category"]

    likelihood = "High" if interaction in ["Login Request", "Query Request"] else "Medium"

    if category in ["Spoofing", "Tampering", "Elevation Of Privilege"]:
        impact = "High"
    else:
        impact = "Medium"

    if likelihood == "High" and impact == "High":
        risk = "Critical"
    else:
        risk = "High"

    return pd.Series([likelihood, impact, risk])


# =========================================================
# RISK JUSTIFICATION (NEW ADDITION)
# =========================================================
def risk_justification(row):
    category = row["Category"]

    if category == "Spoofing":
        return "Identity impersonation may lead to unauthorized access"
    elif category == "Tampering":
        return "Data integrity compromise possible"
    elif category == "Elevation Of Privilege":
        return "Unauthorized privilege escalation risk"
    elif category == "Information Disclosure":
        return "Sensitive data exposure risk"
    elif category == "Denial Of Service":
        return "Service availability disruption risk"
    else:
        return "Security impact identified"


# =========================================================
# GENERATE STAGE 4
# =========================================================
def generate_stage4(clean_df, output_dir):
    print("[STEP 2] AI-assisted risk analysis...")

    risk_df = clean_df.copy()

    risk_df[["Likelihood", "Impact", "Risk"]] = risk_df.apply(
        ai_risk_scoring, axis=1
    )

    # Add Risk Justification
    risk_df["Risk_Justification"] = risk_df.apply(
        risk_justification, axis=1
    )

    stage4_path = f"{output_dir}/pasta_stage4_risk.csv"
    risk_df.to_csv(stage4_path, index=False)

    print("[OK] pasta_stage4_risk.csv created")
    return risk_df


# =========================================================
# MITIGATION ENGINE (STAGE 5)
# =========================================================
MITIGATION_MAP = {
    "Spoofing": "MFA, CAPTCHA, Strong Authentication",
    "Tampering": "Input Validation, Prepared Statements",
    "Information Disclosure": "TLS Encryption, Secure Headers",
    "Denial Of Service": "Rate Limiting, WAF",
    "Elevation Of Privilege": "RBAC, Least Privilege",
    "Repudiation": "Centralized Logging, Audit Trails"
}


def residual_risk(risk):
    if risk == "Critical":
        return "Medium"
    elif risk == "High":
        return "Low"
    else:
        return "Low"


def generate_stage5(stage4_df, output_dir):
    print("[STEP 3] AI-assisted mitigation mapping...")

    mitigation_df = stage4_df.copy()

    mitigation_df["AI_Suggested_Mitigation"] = mitigation_df["Category"].map(
        lambda c: MITIGATION_MAP.get(c, "General Security Controls")
    )

    # Residual Risk (Post-Mitigation)
    mitigation_df["Residual_Risk"] = mitigation_df["Risk"].apply(
        residual_risk
    )

    stage5_path = f"{output_dir}/pasta_stage5_mitigation.csv"
    mitigation_df.to_csv(stage5_path, index=False)

    print("[OK] pasta_stage5_mitigation.csv created")
    return mitigation_df


# =========================================================
# PDF REPORT GENERATION
# =========================================================
def generate_pdf(stage4_df, stage5_df, output_dir):
    print("[STEP 4] Generating PDF report...")

    pdf_path = f"{output_dir}/PASTA_Report.pdf"
    doc = SimpleDocTemplate(pdf_path, pagesize=A4)
    styles = getSampleStyleSheet()
    elements = []

    # 🔹 Helper to wrap text
    def wrap_text(text):
        return Paragraph(str(text), styles["Normal"])

    # 🔹 Convert dataframe to wrapped table
    def create_wrapped_table(df):
        data = [df.columns.tolist()]

        for _, row in df.iterrows():
            data.append([wrap_text(cell) for cell in row])

        # Adjust column widths (IMPORTANT FIX)
        col_widths = [40, 120, 80, 70, 60, 150, 70, 50, 50, 150][:len(df.columns)]

        table = Table(data, repeatRows=1, colWidths=col_widths)

        table.setStyle(
            TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
                ("GRID", (0, 0), (-1, -1), 0.25, colors.black),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 7),  # 🔥 smaller font
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ])
        )

        return table

    # =============================
    # Cover Page
    # =============================
    elements.append(
        Paragraph("<b>AI-Assisted PASTA Threat Modeling Report</b>", styles["Title"])
    )
    elements.append(Spacer(1, 20))

    elements.append(
        Paragraph(
            "Methodology: PASTA + STRIDE<br/>"
            f"Generated On: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            styles["Normal"],
        )
    )

    elements.append(PageBreak())

    # =============================
    # Stage 4 (Split into chunks)
    # =============================
    elements.append(Paragraph("<b>PASTA Stage 4 – Risk Analysis</b>", styles["Heading1"]))
    elements.append(Spacer(1, 15))

    chunk_size = 20  # 🔥 split table into pages
    for i in range(0, len(stage4_df), chunk_size):
        chunk = stage4_df.iloc[i:i+chunk_size]
        elements.append(create_wrapped_table(chunk))
        elements.append(PageBreak())

    # =============================
    # Stage 5 (Split into chunks)
    # =============================
    elements.append(Paragraph("<b>PASTA Stage 5 – Mitigation Strategy</b>", styles["Heading1"]))
    elements.append(Spacer(1, 15))

    for i in range(0, len(stage5_df), chunk_size):
        chunk = stage5_df.iloc[i:i+chunk_size]
        elements.append(create_wrapped_table(chunk))
        elements.append(PageBreak())

    doc.build(elements)

    print(f"[OK] PDF report created at: {pdf_path}")
    return pdf_path
# =========================================================
# MAIN PIPELINE FUNCTION (USED BY STREAMLIT)
# =========================================================
def run_pipeline(input_file="threatlist.csv"):

    output_dir = create_output_dir()

    clean_df = preprocess_threats(input_file, output_dir)

    stage4_df = generate_stage4(clean_df, output_dir)

    stage5_df = generate_stage5(stage4_df, output_dir)

    pdf_path = generate_pdf(stage4_df, stage5_df, output_dir)

    # Update latest folder
    latest_dir = "outputs/latest"
    os.makedirs(latest_dir, exist_ok=True)
    shutil.copytree(output_dir, latest_dir, dirs_exist_ok=True)

    print("[INFO] Latest output updated")
    print("SUCCESS: AI-assisted PASTA pipeline completed.")

    return {
        "output_dir": output_dir,
        "pdf_path": pdf_path,
        "stage4": stage4_df,
        "stage5": stage5_df
    }


# =========================================================
# RUN DIRECTLY
# =========================================================
if __name__ == "__main__":
    run_pipeline()
