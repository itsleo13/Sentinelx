import json
import html
import os


def load_report(path):
    with open(
        path,
        "r",
        encoding="utf-8"
    ) as file:
        return json.load(file)


def esc(value):
    return html.escape(
        str(value)
    )


def generate_html(report):

    target = report.get(
        "target",
        "Unknown"
    )

    risk_score = report.get(
        "risk_score",
        0
    )

    open_ports = report.get(
        "open_ports",
        []
    )

    findings = report.get(
        "findings",
        []
    )

    ml = report.get(
        "ml_analysis",
        {}
    )

    hybrid = report.get(
        "hybrid_analysis",
        {}
    )

    analyst = report.get(
        "ai_assessment",
        {}
    )

    risk_level = hybrid.get(
        "risk_level",
        "Info"
    )

    hybrid_score = hybrid.get(
        "hybrid_score",
        0
    )

    ml_anomaly = hybrid.get(
        "ml_anomaly_score",
        0
    )

    summary = analyst.get(
        "summary",
        "No assessment available."
    )

    top_issue = analyst.get(
        "top_issue",
        {}
    )

    recommendations = analyst.get(
        "recommendations",
        []
    )

    rows = ""

    for port in open_ports:

        rows += f"""
        <tr>
            <td>{esc(port.get("port"))}</td>
            <td>{esc(port.get("protocol", "TCP"))}</td>
            <td>{esc(port.get("service"))}</td>
            <td>{esc(
                port.get("banner") or
                "No banner"
            )}</td>
        </tr>
        """

    recommendation_html = ""

    for item in recommendations:

        recommendation_html += (
            f"<li>{esc(item)}</li>"
        )

    return f"""<!DOCTYPE html>
<html>
<head>

<meta charset="UTF-8">

<title>
SentinelX Security Report
</title>

<style>

body {{
    font-family: Arial, sans-serif;
    margin: 40px;
    background: #f4f6f8;
}}

.container {{
    max-width: 1100px;
    margin: auto;
}}

.header {{
    background: #111827;
    color: white;
    padding: 25px;
    border-radius: 10px;
}}

.cards {{
    display: grid;
    grid-template-columns:
        repeat(4, 1fr);
    gap: 15px;
    margin-top: 20px;
}}

.card {{
    background: white;
    padding: 20px;
    border-radius: 10px;
    box-shadow:
        0 2px 8px
        rgba(0,0,0,0.08);
}}

.card h3 {{
    margin-top: 0;
}}

.section {{
    background: white;
    margin-top: 20px;
    padding: 25px;
    border-radius: 10px;
}}

table {{
    width: 100%;
    border-collapse: collapse;
}}

th, td {{
    padding: 10px;
    border-bottom:
        1px solid #ddd;
    text-align: left;
}}

.badge {{
    display: inline-block;
    padding: 6px 12px;
    border-radius: 20px;
    font-weight: bold;
}}

.info {{
    background: #e5e7eb;
}}

.low {{
    background: #dbeafe;
}}

.medium {{
    background: #fef3c7;
}}

.high {{
    background: #fee2e2;
}}

.critical {{
    background: #fecaca;
}}

</style>

</head>

<body>

<div class="container">

<div class="header">

<h1>
SentinelX Security Report
</h1>

<p>
Target:
<strong>{esc(target)}</strong>
</p>

<p>
Risk Level:
<span class="badge {risk_level.lower()}">
{esc(risk_level)}
</span>
</p>

</div>


<div class="cards">

<div class="card">
<h3>Rule Risk</h3>
<p>{esc(risk_score)}/100</p>
</div>

<div class="card">
<h3>Hybrid Score</h3>
<p>{esc(hybrid_score)}/100</p>
</div>

<div class="card">
<h3>ML Anomaly</h3>
<p>{esc(ml_anomaly)}/100</p>
</div>

<div class="card">
<h3>Open Ports</h3>
<p>{len(open_ports)}</p>
</div>

</div>


<div class="section">

<h2>
AI Security Assessment
</h2>

<p>
{esc(summary)}
</p>

</div>


<div class="section">

<h2>
Top Issue
</h2>

<p>
<strong>
Port:
</strong>
{esc(top_issue.get("port"))}
</p>

<p>
<strong>
Service:
</strong>
{esc(top_issue.get("service"))}
</p>

<p>
<strong>
Severity:
</strong>
{esc(top_issue.get("severity"))}
</p>

<p>
<strong>
Priority:
</strong>
{esc(top_issue.get("priority"))}
</p>

<p>
<strong>
Impact:
</strong>
{esc(top_issue.get("impact"))}
</p>

<p>
<strong>
Action:
</strong>
{esc(top_issue.get("action"))}
</p>

</div>


<div class="section">

<h2>
Open Ports
</h2>

<table>

<tr>
<th>Port</th>
<th>Protocol</th>
<th>Service</th>
<th>Banner</th>
</tr>

{rows}

</table>

</div>


<div class="section">

<h2>
Recommendations
</h2>

<ul>

{recommendation_html}

</ul>

</div>

</div>

</body>
</html>
"""


def create_dashboard(
    json_path,
    output_path=None
):

    report = load_report(
        json_path
    )

    html_content = generate_html(
        report
    )

    if output_path is None:

        base = os.path.splitext(
            json_path
        )[0]

        output_path = (
            base + ".html"
        )

    with open(
        output_path,
        "w",
        encoding="utf-8"
    ) as file:

        file.write(
            html_content
        )

    return output_path