"""
ForensAI - Forensic Report Generation Example
==============================================
Example script demonstrating how to use the ForensicReportGenerator
programmatically in Python code.

This example shows:
1. Basic report generation
2. Advanced usage with all options
3. Integration with existing ForensAI workflows
4. Error handling and validation
"""

import os
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from modules.forensic_report_generator import ForensicReportGenerator


def example_basic_report():
    """
    Example 1: Basic forensic report generation
    Minimum required parameters only.
    """
    print("="*70)
    print("EXAMPLE 1: Basic Forensic Report")
    print("="*70)

    # Required parameters
    case_id = "CASE-2025-001"
    operator = "John Doe"
    master_image = r"C:\cases\evidence.dd"  # Path to your .dd file
    output_dir = r"C:\cases\reports"

    # Create report generator
    generator = ForensicReportGenerator(
        case_id=case_id,
        operator=operator,
        master_image=master_image,
        output_dir=output_dir
    )

    # Generate report (HTML + JSON by default)
    result = generator.generate_report()

    # Check result
    if result['status'] == 'success':
        print(f"\n✓ Report generated successfully!")
        print(f"  HTML: {result['report_html']}")
        print(f"  JSON: {result['manifest_json']}")
    else:
        print(f"\n✗ Report generation failed: {result['summary']}")
        for warning in result['warnings']:
            print(f"  • {warning}")

    return result


def example_advanced_report():
    """
    Example 2: Advanced forensic report with all options
    Includes derived ISO, artifacts, bulk_extractor, and PDF generation.
    """
    print("\n" + "="*70)
    print("EXAMPLE 2: Advanced Forensic Report")
    print("="*70)

    # All parameters
    case_id = "CASE-2025-002"
    operator = "Jane Smith"
    master_image = r"C:\cases\disk_image.dd"
    derived_iso = r"C:\cases\disk_image.iso"
    parsed_artifacts_dir = r"C:\cases\extracted_files"
    bulk_extractor_dir = r"C:\cases\bulk_extractor_output"
    checkpoints_dir = r"C:\cases\checkpoints"
    logfile = r"C:\cases\acquisition.log"
    output_dir = r"C:\cases\reports"

    # Create report generator
    generator = ForensicReportGenerator(
        case_id=case_id,
        operator=operator,
        master_image=master_image,
        output_dir=output_dir,
        derived_iso=derived_iso,
        parsed_artifacts_dir=parsed_artifacts_dir,
        bulk_extractor_dir=bulk_extractor_dir,
        checkpoints_dir=checkpoints_dir,
        logfile=logfile
    )

    # Add custom notes
    generator.notes = "This case involves suspected intellectual property theft. " \
                     "Focus on recent document access and external storage usage."

    # Generate report with all formats including PDF
    result = generator.generate_report(
        formats=['html', 'json', 'pdf'],
        include_screenshots=True
    )

    # Check result
    if result['status'] in ['success', 'partial']:
        print(f"\n✓ Report generated: {result['status']}")
        print(f"  HTML: {result['report_html']}")
        print(f"  PDF:  {result['report_pdf'] or 'Not generated (see warnings)'}")
        print(f"  JSON: {result['manifest_json']}")
        print(f"\n  Summary: {result['summary']}")

        if result['warnings']:
            print("\n  Warnings:")
            for warning in result['warnings']:
                print(f"    • {warning}")
    else:
        print(f"\n✗ Report generation failed: {result['summary']}")

    return result


def example_custom_chain_of_custody():
    """
    Example 3: Adding custom chain of custody entries
    Useful when integrating with existing forensic workflows.
    """
    print("\n" + "="*70)
    print("EXAMPLE 3: Custom Chain of Custody")
    print("="*70)

    case_id = "CASE-2025-003"
    operator = "Forensic Analyst"
    master_image = r"C:\cases\evidence.dd"
    output_dir = r"C:\cases\reports"

    generator = ForensicReportGenerator(
        case_id=case_id,
        operator=operator,
        master_image=master_image,
        output_dir=output_dir
    )

    # Add custom chain of custody entries before report generation
    generator.add_chain_of_custody_entry(
        action="Physical device seized from suspect's residence",
        source="Location: 123 Main St, Evidence Room #5",
        tools="Physical custody transfer",
        hashes=None
    )

    generator.add_chain_of_custody_entry(
        action="Device imaged using write-blocker",
        source="Samsung 1TB SSD (Serial: S3YJNX0M123456)",
        target=master_image,
        tools="Tableau TX1 Write Blocker, dd v8.32",
        hashes={'sha256': 'abc123...', 'md5': 'def456...'}
    )

    # Generate report
    result = generator.generate_report(formats=['html', 'json'])

    print(f"\n✓ Report with {len(generator.chain_of_custody)} chain of custody entries")
    return result


def example_programmatic_artifact_analysis():
    """
    Example 4: Programmatic artifact analysis
    Process artifacts and mark notable items before report generation.
    """
    print("\n" + "="*70)
    print("EXAMPLE 4: Programmatic Artifact Analysis")
    print("="*70)

    case_id = "CASE-2025-004"
    operator = "Security Analyst"
    master_image = r"C:\cases\evidence.dd"
    output_dir = r"C:\cases\reports"

    generator = ForensicReportGenerator(
        case_id=case_id,
        operator=operator,
        master_image=master_image,
        output_dir=output_dir,
        parsed_artifacts_dir=r"C:\cases\extracted"
    )

    # Scan artifacts first
    generator.scan_artifacts()

    # Custom analysis: Mark all executables as high priority
    for artifact in generator.artifacts:
        if artifact.artifact_type == 'executable':
            artifact.priority += 100
            artifact.notable_reasons.append('flagged_for_malware_analysis')

        # Flag recently accessed sensitive files
        if 'password' in artifact.name.lower() or 'credential' in artifact.name.lower():
            artifact.priority += 200
            artifact.notable_reasons.append('contains_credentials')

    # Update statistics
    generator.stats['notable_artifacts'] = sum(1 for a in generator.artifacts if a.notable_reasons)

    print(f"\n  Found {generator.stats['total_files']} files")
    print(f"  Marked {generator.stats['notable_artifacts']} as notable")

    # Generate report with processed artifacts
    result = generator.generate_report(formats=['html', 'json'])

    return result


def example_error_handling():
    """
    Example 5: Proper error handling
    Demonstrates how to handle common errors gracefully.
    """
    print("\n" + "="*70)
    print("EXAMPLE 5: Error Handling")
    print("="*70)

    case_id = "CASE-2025-005"
    operator = "Test Analyst"
    master_image = r"C:\cases\nonexistent.dd"  # Intentionally wrong path
    output_dir = r"C:\cases\reports"

    try:
        generator = ForensicReportGenerator(
            case_id=case_id,
            operator=operator,
            master_image=master_image,
            output_dir=output_dir
        )

        result = generator.generate_report()

        if result['status'] == 'failed':
            print(f"\n✗ Expected failure occurred: {result['summary']}")
            print("  Warnings:")
            for warning in result['warnings']:
                print(f"    • {warning}")

            # Handle the failure appropriately
            print("\n  Action: Verify master image path and retry")

        return result

    except Exception as e:
        print(f"\n✗ Unexpected error: {e}")
        # Log error, notify operator, etc.
        return None


def example_integration_with_acquire():
    """
    Example 6: Integration with ForensAI Acquire module
    Shows how to generate reports after disk acquisition.
    """
    print("\n" + "="*70)
    print("EXAMPLE 6: Integration with Acquire Module")
    print("="*70)

    # Simulate acquisition workflow
    case_id = "CASE-2025-006"
    operator = "Acquisition Specialist"

    # After acquisition completes, these paths would be available
    master_image = r"C:\cases\acquired_disk.dd"
    acquisition_log = r"C:\cases\acquisition.log"
    output_dir = r"C:\cases\reports"

    # Generate report immediately after acquisition
    generator = ForensicReportGenerator(
        case_id=case_id,
        operator=operator,
        master_image=master_image,
        output_dir=output_dir,
        logfile=acquisition_log
    )

    # Add acquisition metadata
    generator.add_chain_of_custody_entry(
        action="Disk acquisition completed using ForensAI Acquire module",
        source="Physical disk /dev/sdb",
        target=master_image,
        tools="ForensAI v1.0, Python dd wrapper"
    )

    result = generator.generate_report()

    print(f"\n✓ Post-acquisition report generated")
    print(f"  Status: {result['status']}")
    print(f"  Files: HTML, JSON")

    return result


def main():
    """
    Main function to run all examples.
    Uncomment the examples you want to run.
    """
    print("\nForensAI - Forensic Report Generation Examples")
    print("=" * 70)
    print("\nNOTE: Update file paths in examples to match your environment!\n")

    # Uncomment the examples you want to run:

    # Example 1: Basic usage
    # example_basic_report()

    # Example 2: Advanced usage with all options
    # example_advanced_report()

    # Example 3: Custom chain of custody
    # example_custom_chain_of_custody()

    # Example 4: Programmatic artifact analysis
    # example_programmatic_artifact_analysis()

    # Example 5: Error handling
    example_error_handling()

    # Example 6: Integration with acquire module
    # example_integration_with_acquire()

    print("\n" + "="*70)
    print("Examples complete!")
    print("="*70)


if __name__ == '__main__':
    main()
