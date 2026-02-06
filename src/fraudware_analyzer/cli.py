"""
Command Line Interface

This module provides the CLI for Fraudware Analyzer.
"""

import sys
import click
from pathlib import Path
from typing import Optional

from fraudware_analyzer import Analyzer
from fraudware_analyzer.report import JSONReporter, HTMLReporter


@click.group()
@click.version_option(version="0.1.0")
def main():
    """Fraudware Analyzer - Banking Trojan Detection Tool"""
    pass


@main.command()
@click.argument("file_path", type=click.Path(exists=True))
@click.option("--verbose", "-v", is_flag=True, help="Verbose output")
@click.option("--output", "-o", type=click.Path(), help="Output file path")
@click.option("--format", "-f", type=click.Choice(["json", "html", "text"]), default="text", help="Output format")
@click.option("--model", "-m", type=click.Path(), help="Path to ML model")
@click.option("--rules", "-r", type=click.Path(), help="Path to YARA rules")
def analyze(file_path: str, verbose: bool, output: Optional[str], format: str, model: Optional[str], rules: Optional[str]):
    """
    Analyze a PE file for malware indicators.

    FILE_PATH: Path to the file to analyze
    """
    # Initialize analyzer
    analyzer = Analyzer(
        model_path=model,
        yara_rules_path=rules,
    )

    # Perform analysis
    if verbose:
        click.echo(f"Analyzing: {file_path}")

    result = analyzer.analyze(file_path)

    # Generate output
    if format == "json":
        reporter = JSONReporter()
    elif format == "html":
        reporter = HTMLReporter()
    else:
        reporter = None

    if reporter:
        report_path = output or f"{file_path}.{format}"
        reporter.generate(result, report_path)
        if verbose:
            click.echo(f"Report saved to: {report_path}")
    else:
        # Print to console
        click.echo(f"\n=== Analysis Results ===")
        click.echo(f"File: {result.file_path}")
        click.echo(f"Family: {result.family}")
        click.echo(f"Confidence: {result.confidence:.2%}")
        click.echo(f"Risk Score: {result.risk_score}/100")
        click.echo(f"Malicious: {'Yes' if result.is_malicious else 'No'}")

        if result.suspicious_apis:
            click.echo(f"\nSuspicious APIs ({len(result.suspicious_apis)}):")
            for api in result.suspicious_apis[:10]:
                click.echo(f"  - {api}")

        if result.suspicious_strings:
            click.echo(f"\nSuspicious Strings ({len(result.suspicious_strings)}):")
            for s in result.suspicious_strings[:5]:
                click.echo(f"  - {s.get('value', '')[:50]}...")

        if result.errors:
            click.echo(f"\nErrors:")
            for error in result.errors:
                click.echo(f"  - {error}")

    # Exit with appropriate code
    sys.exit(1 if result.is_malicious else 0)


@main.command()
@click.argument("directory", type=click.Path(exists=True, file_okay=False))
@click.option("--output", "-o", type=click.Path(), default="./reports", help="Output directory")
@click.option("--format", "-f", type=click.Choice(["json", "html"]), default="html", help="Output format")
@click.option("--recursive", "-r", is_flag=True, help="Recursive directory scan")
@click.option("--threads", "-t", type=int, default=1, help="Number of threads")
def batch(directory: str, output: str, format: str, recursive: bool, threads: int):
    """
    Batch analyze files in a directory.

    DIRECTORY: Directory containing files to analyze
    """
    # Find files
    path = Path(directory)
    if recursive:
        files = list(path.rglob("*.exe")) + list(path.rglob("*.dll"))
    else:
        files = list(path.glob("*.exe")) + list(path.glob("*.dll"))

    if not files:
        click.echo("No PE files found in directory.")
        return

    click.echo(f"Found {len(files)} files to analyze")

    # Initialize analyzer
    analyzer = Analyzer()

    # Analyze
    results = []
    for i, file_path in enumerate(files, 1):
        click.echo(f"[{i}/{len(files)}] Analyzing: {file_path.name}")
        try:
            result = analyzer.analyze(str(file_path))
            results.append(result)
        except Exception as e:
            click.echo(f"  Error: {e}", err=True)

    # Generate summary
    malicious = sum(1 for r in results if r.is_malicious)
    click.echo(f"\n=== Batch Analysis Summary ===")
    click.echo(f"Total files: {len(results)}")
    click.echo(f"Malicious: {malicious}")
    click.echo(f"Clean: {len(results) - malicious}")

    # Save reports
    output_path = Path(output)
    output_path.mkdir(parents=True, exist_ok=True)

    for result in results:
        report_file = output_path / f"{Path(result.file_path).stem}.{format}"
        if format == "json":
            reporter = JSONReporter()
        else:
            reporter = HTMLReporter()
        reporter.generate(result, str(report_file))

    click.echo(f"\nReports saved to: {output}")


if __name__ == "__main__":
    main()
