"""
ForensAI - Forensic Report Generation Tool
==========================================
Command-line interface for generating comprehensive forensic evidence reports.

Usage:
    python generate_forensic_report.py --case-id CASE-2025-001 \\
        --operator "Analyst Name" \\
        --master-image path/to/evidence.dd \\
        --output-dir path/to/reports

Author: ForensAI Team
"""

import sys
import os
import argparse
import json
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.forensic_report_generator import ForensicReportGenerator


def validate_inputs(args):
    """
    Validate input arguments.

    Args:
        args: Parsed command-line arguments

    Returns:
        Tuple of (valid: bool, errors: list)
    """
    errors = []

    if not os.path.exists(args.master_image):
        errors.append(f"Master image not found: {args.master_image}")
    elif not os.path.isfile(args.master_image):
        errors.append(f"Master image is not a file: {args.master_image}")

    if args.derived_iso:
        if not os.path.exists(args.derived_iso):
            errors.append(f"Derived ISO not found: {args.derived_iso}")
        elif not os.path.isfile(args.derived_iso):
            errors.append(f"Derived ISO is not a file: {args.derived_iso}")

    if args.artifacts_dir:
        if not os.path.exists(args.artifacts_dir):
            errors.append(f"Artifacts directory not found: {args.artifacts_dir}")
        elif not os.path.isdir(args.artifacts_dir):
            errors.append(f"Artifacts path is not a directory: {args.artifacts_dir}")

    if args.bulk_extractor_dir:
        if not os.path.exists(args.bulk_extractor_dir):
            errors.append(f"Bulk extractor directory not found: {args.bulk_extractor_dir}")
        elif not os.path.isdir(args.bulk_extractor_dir):
            errors.append(f"Bulk extractor path is not a directory: {args.bulk_extractor_dir}")

    if not args.case_id or len(args.case_id.strip()) == 0:
        errors.append("Case ID cannot be empty")

    if not args.operator or len(args.operator.strip()) == 0:
        errors.append("Operator name cannot be empty")

    return (len(errors) == 0, errors)


def print_banner():
    """Print application banner."""
    banner = """
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║      ForensAI - Forensic Evidence Report Generator           ║
║                                                               ║
║  Generate court-admissible forensic evidence reports with    ║
║  chain of custody, hash verification, and artifact analysis  ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
"""
    print(banner)


def print_summary(result):
    """
    Print human-readable summary of report generation.

    Args:
        result: Result dictionary from report generator
    """
    print("\n" + "="*70)
    print("REPORT GENERATION SUMMARY")
    print("="*70)

    status_symbol = {
        'success': '✓',
        'partial': '⚠',
        'failed': '✗'
    }

    symbol = status_symbol.get(result['status'], '?')
    print(f"\nStatus: {symbol} {result['status'].upper()}")
    print(f"Case ID: {result['case_id']}")
    print(f"\n{result['summary']}")

    if result.get('warnings'):
        print("\n⚠ WARNINGS:")
        for warning in result['warnings']:
            print(f"  • {warning}")

    print("\n" + "-"*70)
    print("Generated Files:")
    print("-"*70)

    if result.get('report_html'):
        print(f"  HTML Report:  {result['report_html']}")
    if result.get('report_pdf'):
        print(f"  PDF Report:   {result['report_pdf']}")
    if result.get('manifest_json'):
        print(f"  JSON Manifest: {result['manifest_json']}")
    if result.get('logfile'):
        print(f"  Logfile Copy:  {result['logfile']}")

    print("="*70 + "\n")


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description='ForensAI Forensic Evidence Report Generator',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:

  # Basic usage with HTML and JSON output:
  python generate_forensic_report.py \\
    --case-id CASE-2025-001 \\
    --operator "John Doe" \\
    --master-image C:\\cases\\evidence.dd \\
    --output-dir C:\\cases\\reports

  # Full analysis with all outputs:
  python generate_forensic_report.py \\
    --case-id CASE-2025-001 \\
    --operator "Jane Smith" \\
    --master-image /mnt/evidence/disk.dd \\
    --derived-iso /mnt/evidence/disk.iso \\
    --artifacts-dir /mnt/evidence/extracted \\
    --bulk-extractor-dir /mnt/evidence/bulk_extractor \\
    --output-dir /mnt/evidence/reports \\
    --formats html json pdf \\
    --verbose

  # With logfile integration:
  python generate_forensic_report.py \\
    --case-id CASE-2025-002 \\
    --operator "Analyst" \\
    --master-image evidence.dd \\
    --logfile acquisition.log \\
    --output-dir reports \\
    --formats html json

Required Arguments:
  --case-id           Unique case identifier (e.g., CASE-2025-001)
  --operator          Name of the analyst/operator
  --master-image      Path to the master evidence image (.dd file)
  --output-dir        Directory where reports will be saved

Optional Arguments:
  --derived-iso       Path to derived ISO file (if created)
  --artifacts-dir     Directory containing extracted/parsed artifacts
  --bulk-extractor-dir Directory containing bulk_extractor output
  --checkpoints-dir   Directory containing checkpoints
  --logfile           Path to processing/acquisition logfile
  --formats           Output formats: html, json, pdf (default: html json)
  --include-screenshots Include screenshots in report
  --verbose, -v       Enable verbose logging

For more information:
  https://github.com/forensai/forensai
"""
    )

    required_group = parser.add_argument_group('required arguments')
    required_group.add_argument('--case-id', required=True,
                               help='Unique case identifier (e.g., CASE-2025-001)')
    required_group.add_argument('--operator', required=True,
                               help='Name of analyst/operator generating report')
    required_group.add_argument('--master-image', required=True,
                               help='Path to master evidence image (.dd file)')
    required_group.add_argument('--output-dir', required=True,
                               help='Directory where reports will be saved')

    optional_group = parser.add_argument_group('optional arguments')
    optional_group.add_argument('--derived-iso',
                               help='Path to derived ISO file (optional)')
    optional_group.add_argument('--artifacts-dir',
                               help='Directory containing parsed artifacts')
    optional_group.add_argument('--bulk-extractor-dir',
                               help='Directory containing bulk_extractor output')
    optional_group.add_argument('--checkpoints-dir',
                               help='Directory containing checkpoints')
    optional_group.add_argument('--logfile',
                               help='Path to processing/acquisition logfile')

    output_group = parser.add_argument_group('output configuration')
    output_group.add_argument('--formats', nargs='+',
                             default=['html', 'json'],
                             choices=['html', 'json', 'pdf'],
                             help='Output formats (default: html json)')
    output_group.add_argument('--include-screenshots', action='store_true',
                             help='Include screenshots in report')
    output_group.add_argument('--json-output', action='store_true',
                             help='Output result as JSON only (no banner or summary)')
    output_group.add_argument('--verbose', '-v', action='store_true',
                             help='Enable verbose logging')

    args = parser.parse_args()

    if args.verbose:
        import logging
        logging.basicConfig(
            level=logging.DEBUG,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )

    if not args.json_output:
        print_banner()
        print(f"Case ID: {args.case_id}")
        print(f"Operator: {args.operator}")
        print(f"Master Image: {args.master_image}")
        print(f"Output Directory: {args.output_dir}")
        print(f"Output Formats: {', '.join(args.formats)}")
        print("\nValidating inputs...")

    valid, errors = validate_inputs(args)
    if not valid:
        if args.json_output:
            result = {
                'status': 'failed',
                'case_id': args.case_id,
                'report_pdf': None,
                'report_html': None,
                'manifest_json': None,
                'logfile': None,
                'summary': 'Input validation failed',
                'warnings': errors
            }
            print(json.dumps(result, indent=2))
        else:
            print("\n✗ Validation failed:")
            for error in errors:
                print(f"  • {error}")
            print("\nUse --help for usage information.")
        sys.exit(1)

    if not args.json_output:
        print("✓ Validation passed\n")
        print("Generating forensic evidence report...")
        print("This may take several minutes depending on evidence size.\n")

    try:
        os.makedirs(args.output_dir, exist_ok=True)

        generator = ForensicReportGenerator(
            case_id=args.case_id,
            operator=args.operator,
            master_image=args.master_image,
            output_dir=args.output_dir,
            derived_iso=args.derived_iso,
            parsed_artifacts_dir=args.artifacts_dir,
            bulk_extractor_dir=args.bulk_extractor_dir,
            checkpoints_dir=args.checkpoints_dir,
            logfile=args.logfile
        )

        result = generator.generate_report(
            formats=args.formats,
            include_screenshots=args.include_screenshots
        )

        if args.json_output:
            print(json.dumps(result, indent=2))
        else:
            print_summary(result)

        exit_code = 0 if result['status'] in ['success', 'partial'] else 1
        sys.exit(exit_code)

    except KeyboardInterrupt:
        if args.json_output:
            result = {
                'status': 'failed',
                'case_id': args.case_id,
                'report_pdf': None,
                'report_html': None,
                'manifest_json': None,
                'logfile': None,
                'summary': 'Report generation interrupted by user',
                'warnings': ['Process interrupted']
            }
            print(json.dumps(result, indent=2))
        else:
            print("\n\n✗ Report generation interrupted by user.")
        sys.exit(1)

    except Exception as e:
        if args.json_output:
            result = {
                'status': 'failed',
                'case_id': args.case_id,
                'report_pdf': None,
                'report_html': None,
                'manifest_json': None,
                'logfile': None,
                'summary': f'Unexpected error: {str(e)}',
                'warnings': [str(e)]
            }
            print(json.dumps(result, indent=2))
        else:
            print(f"\n✗ Unexpected error: {e}")
            if args.verbose:
                import traceback
                traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
