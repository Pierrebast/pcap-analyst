import os
import json
from datetime import datetime
from dotenv import load_dotenv
import anthropic

from config import REPORT_DIR, MODEL, MAX_TOKENS

load_dotenv()

def generate_report(findings, pcap_filename):
    client = anthropic.Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))
    if not findings:
        summary = "No suspicious activity detected in this capture."
    else:
        summary = json.dumps(findings, indent=2)

    prompt = f"""You are a network security analyst. 
    I have analyzed a pcap file called '{pcap_filename}' and found the following suspicious activity:

    {summary}

    Please provide:
    1. A plain English summary of what happened
    2. The severity of each finding (Low / Medium / High)
    3. What the attacker may have been trying to do
    4. Recommended actions to investigate or mitigate

    Be concise and technical but understandable."""

    message = client.messages.create(
        model=MODEL,
        max_tokens=MAX_TOKENS,
        messages=[
            {"role": "user", "content": prompt}
        ]
    )

    report_text = message.content[0].text

    base_name = os.path.basename(pcap_filename)  # gives "test.pcap"
    filename = base_name + "_" + datetime.now().strftime("%Y%m%d_%H%M%S") + ".md"
    filepath = os.path.join(REPORT_DIR, filename)
    with open(filepath,"w") as f:
        f.write(report_text)

    return report_text