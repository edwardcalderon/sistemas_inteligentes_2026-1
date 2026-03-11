from pathlib import Path
from reportlab.lib.pagesizes import LETTER
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, PageBreak

REPORT_TITLE = "Multimodal Model Evaluation Report"
AUTHOR = "Edward Calderon"
COURSE = "Sistemas Inteligentes 2026-1"
EXERCISE = "Week 5 / Exercise 2"
OUTPUT_PDF = str(Path(__file__).with_name("multimodal_model_evaluation_report.pdf"))

SECTIONS = [
    (
        "Abstract",
        "This report presents an academic evaluation of a Qwen2.5-VL multimodal agent "
        "covering audio+image reasoning, OCR comparison, and iterative conversation."
    ),
    (
        "Methodology",
        "The methodology uses observation, interpretation, and implication as a structured "
        "framework to assess model behavior and practical robustness."
    ),
    (
        "Activity 1: Multimodal Audio + Image",
        "Qwen2.5-VL shows strong intent grounding when audio transcription quality is high. "
        "Primary limitation: ASR noise cascades into multimodal reasoning."
    ),
    (
        "Activity 2: OCR Comparison",
        "Compared with BLIP-2, Qwen2.5-VL better preserves text semantics and contextual binding "
        "in text-rich images."
    ),
    (
        "Activity 3: Iterative Conversation",
        "The model maintains better conversational consistency and can refine answers under "
        "evidence-oriented follow-up prompts."
    ),
    (
        "Conclusions",
        "Qwen2.5-VL is preferable for integrated multimodal reasoning pipelines, while BLIP-2 "
        "remains useful for lightweight descriptive tasks."
    ),
]


def build_report(output_path: str = OUTPUT_PDF) -> str:
    styles = getSampleStyleSheet()
    doc = SimpleDocTemplate(output_path, pagesize=LETTER)
    story = []

    story.append(Spacer(1, 120))
    story.append(Paragraph(f"<b>{REPORT_TITLE}</b>", styles["Title"]))
    story.append(Spacer(1, 24))
    story.append(Paragraph(f"Author: {AUTHOR}", styles["Heading3"]))
    story.append(Spacer(1, 12))
    story.append(Paragraph(f"Course: {COURSE}", styles["Normal"]))
    story.append(Paragraph(EXERCISE, styles["Normal"]))
    story.append(PageBreak())

    story.append(Paragraph("<b>Index</b>", styles["Heading1"]))
    for i, (title, _) in enumerate(SECTIONS, start=1):
        story.append(Paragraph(f"{i}. {title}", styles["Normal"]))
    story.append(PageBreak())

    for title, content in SECTIONS:
        story.append(Paragraph(f"<b>{title}</b>", styles["Heading2"]))
        story.append(Spacer(1, 8))
        story.append(Paragraph(content, styles["BodyText"]))
        story.append(Spacer(1, 16))

    doc.build(story)
    return output_path


if __name__ == "__main__":
    path = build_report()
    print(f"PDF generated: {path}")
