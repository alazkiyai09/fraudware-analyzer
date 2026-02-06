"""
HTML Reporter Module

This module generates HTML reports from analysis results.
"""

from typing import Dict, Any
from fraudware_analyzer.result import AnalysisResult
from datetime import datetime


class HTMLReporter:
    """
    Generates HTML format reports from analysis results.
    """

    def generate(self, result: AnalysisResult, output_path: str) -> None:
        """
        Generate an HTML report.

        Args:
            result: AnalysisResult object
            output_path: Path to save the report
        """
        html_content = self._generate_html(result)

        with open(output_path, 'w') as f:
            f.write(html_content)

    def _generate_html(self, result: AnalysisResult) -> str:
        """Generate HTML content from analysis result."""
        risk_color = self._get_risk_color(result.risk_score)
        risk_class = "high-risk" if result.risk_score >= 70 else "medium-risk" if result.risk_score >= 40 else "low-risk"

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Fraudware Analyzer Report - {result.file_path}</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}

        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            line-height: 1.6;
            color: #333;
            background: #f5f5f5;
        }}

        .container {{
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }}

        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            border-radius: 10px;
            margin-bottom: 20px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }}

        .header h1 {{
            font-size: 28px;
            margin-bottom: 10px;
        }}

        .header .subtitle {{
            opacity: 0.9;
            font-size: 14px;
        }}

        .summary {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 20px;
        }}

        .summary-card {{
            background: white;
            padding: 20px;
            border-radius: 10px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}

        .summary-card h3 {{
            font-size: 12px;
            text-transform: uppercase;
            color: #666;
            margin-bottom: 10px;
        }}

        .summary-card .value {{
            font-size: 32px;
            font-weight: bold;
            color: #333;
        }}

        .summary-card.risk .value {{
            color: {risk_color};
        }}

        .section {{
            background: white;
            padding: 20px;
            border-radius: 10px;
            margin-bottom: 20px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}

        .section h2 {{
            font-size: 20px;
            margin-bottom: 15px;
            color: #333;
            border-bottom: 2px solid #667eea;
            padding-bottom: 10px;
        }}

        .badge {{
            display: inline-block;
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 12px;
            font-weight: 600;
            margin-right: 5px;
            margin-bottom: 5px;
        }}

        .badge.danger {{ background: #fee; color: #c33; }}
        .badge.warning {{ background: #ffc; color: #960; }}
        .badge.info {{ background: #eef; color: #36c; }}
        .badge.success {{ background: #efe; color: #3a3; }}

        table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 10px;
        }}

        table th, table td {{
            padding: 10px;
            text-align: left;
            border-bottom: 1px solid #eee;
        }}

        table th {{
            background: #f8f9fa;
            font-weight: 600;
            font-size: 12px;
            text-transform: uppercase;
        }}

        .code-block {{
            background: #2d2d2d;
            color: #f8f8f2;
            padding: 15px;
            border-radius: 5px;
            overflow-x: auto;
            font-family: 'Monaco', 'Menlo', monospace;
            font-size: 12px;
            line-height: 1.5;
        }}

        .risk-bar {{
            height: 20px;
            background: #eee;
            border-radius: 10px;
            overflow: hidden;
            margin-top: 10px;
        }}

        .risk-bar-fill {{
            height: 100%;
            background: linear-gradient(90deg, #4caf50, #ffeb3b, #f44336);
            transition: width 0.3s;
        }}

        .footer {{
            text-align: center;
            padding: 20px;
            color: #666;
            font-size: 12px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Malware Analysis Report</h1>
            <div class="subtitle">Generated by Fraudware Analyzer</div>
            <div class="subtitle">{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</div>
        </div>

        <div class="summary">
            <div class="summary-card">
                <h3>File Name</h3>
                <div class="value" style="font-size: 16px;">{result.file_path.split('/')[-1]}</div>
            </div>
            <div class="summary-card">
                <h3>Malware Family</h3>
                <div class="value" style="font-size: 20px;">{result.family}</div>
            </div>
            <div class="summary-card">
                <h3>Confidence</h3>
                <div class="value" style="font-size: 20px;">{result.confidence:.1%}</div>
            </div>
            <div class="summary-card risk">
                <h3>Risk Score</h3>
                <div class="value" style="font-size: 20px;">{result.risk_score}/100</div>
                <div class="risk-bar">
                    <div class="risk-bar-fill" style="width: {result.risk_score}%;"></div>
                </div>
            </div>
        </div>

        {self._generate_pe_section(result)}
        {self._generate_api_section(result)}
        {self._generate_strings_section(result)}
        {self._generate_yara_section(result)}

        <div class="footer">
            Generated by Fraudware Analyzer v0.1.0<br>
            For educational and research purposes only
        </div>
    </div>
</body>
</html>"""

    def _get_risk_color(self, score: int) -> str:
        """Get color based on risk score."""
        if score >= 70:
            return "#f44336"
        elif score >= 40:
            return "#ff9800"
        else:
            return "#4caf50"

    def _generate_pe_section(self, result: AnalysisResult) -> str:
        """Generate PE information section."""
        if not result.pe_info:
            return ""

        pe_info = result.pe_info
        is_packed = "Yes" if pe_info.get("is_packed") else "No"

        sections_html = ""
        for section in pe_info.get("sections", [])[:10]:
            name = section.get("name", "")
            is_exec = "executable" if section.get("is_executable") else ""
            sections_html += f"""
            <tr>
                <td>{name}</td>
                <td>{section.get('virtual_address', '')}</td>
                <td>{section.get('size', 0)}</td>
                <td>{section.get('entropy', 0):.2f}</td>
                <td>{is_exec}</td>
            </tr>"""

        return f"""
        <div class="section">
            <h2>PE File Information</h2>
            <table>
                <tr><th>Property</th><th>Value</th></tr>
                <tr><td>Machine Type</td><td>{pe_info.get('machine', 'N/A')}</td></tr>
                <tr><td>Is DLL</td><td>{'Yes' if pe_info.get('is_dll') else 'No'}</td></tr>
                <tr><td>Is 64-bit</td><td>{'Yes' if pe_info.get('is_64bit') else 'No'}</td></tr>
                <tr><td>Is Packed</td><td>{is_packed}</td></tr>
                <tr><td>Number of Sections</td><td>{len(pe_info.get('sections', []))}</td></tr>
            </table>

            <h3 style="margin-top: 20px;">Sections</h3>
            <table>
                <tr><th>Name</th><th>Virtual Address</th><th>Size</th><th>Entropy</th><th>Attributes</th></tr>
                {sections_html}
            </table>
        </div>"""

    def _generate_api_section(self, result: AnalysisResult) -> str:
        """Generate API analysis section."""
        if not result.suspicious_apis:
            return ""

        apis_html = ""
        for api in result.suspicious_apis[:50]:
            apis_html += f'<span class="badge warning">{api}</span>'

        return f"""
        <div class="section">
            <h2>Suspicious API Calls</h2>
            <p>Found {len(result.suspicious_apis)} suspicious API calls</p>
            <div style="margin-top: 10px;">
                {apis_html}
            </div>
        </div>"""

    def _generate_strings_section(self, result: AnalysisResult) -> str:
        """Generate strings analysis section."""
        if not result.suspicious_strings:
            return ""

        strings_html = ""
        for s in result.suspicious_strings[:20]:
            value = s.get("value", "")[:100]
            string_type = s.get("type", "unknown")
            strings_html += f"""
            <tr>
                <td><span class="badge danger">{string_type}</span></td>
                <td style="font-family: monospace;">{value}</td>
            </tr>"""

        return f"""
        <div class="section">
            <h2>Suspicious Strings</h2>
            <p>Found {len(result.suspicious_strings)} suspicious strings</p>
            <table>
                <tr><th>Type</th><th>Value</th></tr>
                {strings_html}
            </table>
        </div>"""

    def _generate_yara_section(self, result: AnalysisResult) -> str:
        """Generate YARA matches section."""
        if not result.yara_matches:
            return ""

        matches_html = ""
        for match in result.yara_matches:
            rule = match.get("rule", "unknown")
            tags = ", ".join(match.get("tags", []))
            matches_html += f"""
            <tr>
                <td>{rule}</td>
                <td>{tags if tags else 'N/A'}</td>
            </tr>"""

        return f"""
        <div class="section">
            <h2>YARA Rule Matches</h2>
            <p>Found {len(result.yara_matches)} matching rules</p>
            <table>
                <tr><th>Rule</th><th>Tags</th></tr>
                {matches_html}
            </table>
        </div>"""
