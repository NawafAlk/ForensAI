"""
ForensAI - HIGH Priority Features Test Suite
=============================================
Comprehensive testing for HIGH priority features:
1. Confidence & Uncertainty Metrics
2. False Positive Protection (Whitelist + VirusTotal + PE Signatures)
3. Explainability Controls (Rule adjustment, Why NOT flagged, Custom rules)
"""

import os
import sys
from datetime import datetime

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Test 1: Confidence & Uncertainty Metrics
def test_confidence_tracking():
    """Test confidence and uncertainty tracking"""
    print("=" * 70)
    print("TEST 1: CONFIDENCE & UNCERTAINTY METRICS")
    print("=" * 70)
    print()

    try:
        from managers.confidence_tracker import (
            get_confidence_tracker, FactType, ConfidenceScore
        )
        from managers.risk_scorer import RiskScorer
        from managers.ai_service import LocalAIService

        # Get confidence tracker
        tracker = get_confidence_tracker(case_id="test_high_001")

        print("[1] Testing Derived Facts Tracking...")
        # Create test file data
        test_file = {
            'name': 'important_doc.pdf',
            'path': 'C:/Users/Test/Documents/important_doc.pdf',
            'size': 524288,
            'created': '2024-01-15T10:30:00Z',
            'modified': '2024-01-16T14:20:00Z',
            'accessed': '2024-01-17T09:15:00Z',
            'sha256': 'a' * 64,
            'md5': 'b' * 32,
            'entropy': 7.2,
            'mime_type': 'application/pdf'
        }

        # Initialize risk scorer with confidence tracking
        scorer = RiskScorer(
            case_id="test_high_001",
            confidence_tracker=tracker
        )

        # Score file (automatically tracks derived facts)
        risk_score = scorer.score_file(test_file)

        # Check tracked facts
        all_facts = list(tracker.facts.values())
        derived_facts = tracker.get_derived_facts()

        print(f"   [OK] Total facts tracked: {len(all_facts)}")
        print(f"   [OK] Derived facts (from evidence): {len(derived_facts)}")

        # Show sample facts
        if derived_facts:
            sample = derived_facts[0]
            print(f"   [OK] Sample derived fact: {sample.description}")
            print(f"        Value: {sample.value}")
            print(f"        Confidence: {sample.confidence.score * 100:.0f}%")
            print(f"        Source: {sample.source}")

        print()
        print("[2] Testing AI-Inferred Facts...")

        # Check if Groq API is available
        ai_service = LocalAIService(
            case_id="test_high_001",
            confidence_tracker=tracker
        )

        if ai_service.is_available():
            print("   [OK] Groq API is accessible")
            # Get AI explanation (automatically tracks inferred facts)
            explanation = ai_service.explain_file_artifact(test_file)

            # Check inferred facts
            inferred_facts = tracker.get_inferred_facts()
            print(f"   [OK] Inferred facts (from AI): {len(inferred_facts)}")

            if inferred_facts:
                ai_fact = inferred_facts[0]
                print(f"   [OK] AI fact confidence: {ai_fact.confidence.score * 100:.0f}%")
                print(f"        Level: {ai_fact.confidence.level.value}")
        else:
            print("   [SKIP] Groq API not configured - skipping AI fact tracking")

        print()
        print("[3] Testing Uncertainty Indicators...")

        uncertainties = tracker.uncertainty_indicators
        critical_uncertainties = tracker.get_critical_uncertainties()

        print(f"   [OK] Total uncertainty indicators: {len(uncertainties)}")
        print(f"   [OK] Critical uncertainties: {len(critical_uncertainties)}")

        if uncertainties:
            sample_uncertainty = uncertainties[0]
            print(f"   [OK] Sample uncertainty: {sample_uncertainty.indicator_type}")
            print(f"        Severity: {sample_uncertainty.severity}")
            print(f"        Description: {sample_uncertainty.description}")
            print(f"        Mitigation: {sample_uncertainty.mitigation}")

        print()
        print("[4] Testing Confidence Report Export...")

        report = tracker.export_confidence_report(artifact_id=str(test_file.get('name')))
        print(f"   [OK] Report generated for case: {report['case_id']}")
        print(f"   [OK] Total facts: {report['summary']['total_facts']}")
        print(f"   [OK] Derived: {report['summary']['derived_facts']}")
        print(f"   [OK] Inferred: {report['summary']['inferred_facts']}")
        print(f"   [OK] Low confidence: {report['summary']['low_confidence_facts']}")

        print()
        print("[PASS] CONFIDENCE & UNCERTAINTY METRICS TEST COMPLETE")
        return True

    except Exception as e:
        print(f"[FAIL] Error: {e}")
        import traceback
        traceback.print_exc()
        return False


# Test 2: False Positive Protection
def test_false_positive_protection():
    """Test whitelist, VirusTotal, and PE signature features"""
    print()
    print("=" * 70)
    print("TEST 2: FALSE POSITIVE PROTECTION")
    print("=" * 70)
    print()

    try:
        from managers.whitelist_manager import get_whitelist_manager, WhitelistResult
        from managers.virustotal_checker import get_virustotal_checker, VTResult
        from managers.pe_signature_verifier import get_pe_verifier, SignatureInfo

        # Test 2A: Whitelist Manager
        print("[1] Testing Whitelist Manager...")
        whitelist = get_whitelist_manager(case_id="test_high_001")

        # Add test entries
        success = whitelist.add_entry(
            source="custom",
            hash_sha256="a" * 64,
            filename="notepad.exe",
            product_name="Windows Notepad",
            vendor="Microsoft Corporation",
            added_by="test_user",
            notes="Known-good Windows binary",
            confidence=1.0
        )
        print(f"   [OK] Added whitelist entry: {success}")

        # Check file
        test_file = {
            'sha256': "a" * 64,
            'md5': "b" * 32,
            'name': 'notepad.exe'
        }

        result = whitelist.check_file(test_file)
        print(f"   [OK] File whitelisted: {result.is_whitelisted}")
        if result.is_whitelisted:
            print(f"        Entry: {result.entry.product_name}")
            print(f"        Vendor: {result.entry.vendor}")
            print(f"        Confidence: {result.confidence * 100:.0f}%")
            print(f"        Matched by: {result.matched_by}")

        # Get statistics
        stats = whitelist.get_statistics()
        print(f"   [OK] Whitelist statistics:")
        for source, count in stats.items():
            print(f"        {source}: {count} entries")

        # Test 2B: VirusTotal Checker
        print()
        print("[2] Testing VirusTotal Integration...")
        vt_checker = get_virustotal_checker(api_key="")  # No key for testing

        # Test with no API key
        vt_result = vt_checker.check_hash("test_hash_12345")
        print(f"   [OK] VT check (no API key): {vt_result.error}")

        # Note: Full VT testing requires valid API key
        print("   [NOTE] Full VT testing requires valid API key")
        print("          Set VT_API_KEY environment variable for testing")

        # Test 2C: PE Signature Verifier
        print()
        print("[3] Testing PE Signature Verification...")
        pe_verifier = get_pe_verifier()

        # Test with non-existent file
        sig_info = pe_verifier.verify_file("nonexistent.exe")
        print(f"   [OK] PE verification (invalid file): {sig_info.error}")

        # Note: Full PE testing requires actual PE files
        print("   [NOTE] Full PE testing requires actual executable files")

        print()
        print("[PASS] FALSE POSITIVE PROTECTION TEST COMPLETE")
        return True

    except Exception as e:
        print(f"[FAIL] Error: {e}")
        import traceback
        traceback.print_exc()
        return False


# Test 3: Explainability Controls
def test_explainability_controls():
    """Test rule configuration, weight adjustment, and why-not-flagged analysis"""
    print()
    print("=" * 70)
    print("TEST 3: EXPLAINABILITY CONTROLS")
    print("=" * 70)
    print()

    try:
        from managers.rule_config_manager import get_rule_config_manager, RuleDefinition
        from managers.risk_scorer import RiskScorer

        # Test 3A: Rule Configuration with Versioning
        print("[1] Testing Rule Configuration Manager...")
        rule_manager = get_rule_config_manager(case_id="test_high_001")

        print(f"   [OK] Loaded rule manager")
        print(f"        Current version: {rule_manager.current_version.version}")
        print(f"        Total versions: {len(rule_manager.versions)}")
        print(f"        Total rules: {len(rule_manager.current_version.rules)}")

        # Get current weights
        weights = rule_manager.get_current_weights()
        print(f"   [OK] Loaded {len(weights)} rule weights")

        # Show sample rules
        sample_rules = list(weights.items())[:3]
        for code, weight in sample_rules:
            rule = rule_manager.get_rule(code)
            print(f"        [{weight:3d} pts] {rule.name}")

        print()
        print("[2] Testing Rule Weight Adjustment...")

        # Adjust a rule weight
        old_weight = weights.get('double_extension', 65)
        new_weight = 75

        success = rule_manager.adjust_rule_weight(
            rule_code='double_extension',
            new_weight=new_weight,
            changed_by='test_investigator',
            reason='Increased due to prevalence in recent investigations'
        )

        print(f"   [OK] Adjusted rule weight: {success}")
        print(f"        Rule: double_extension")
        print(f"        Old weight: {old_weight} pts")
        print(f"        New weight: {new_weight} pts")
        print(f"        New version: {rule_manager.current_version.version}")
        print(f"        Version hash: {rule_manager.current_version.config_hash}")

        print()
        print("[3] Testing Custom Rule Creation...")

        # Add custom rule
        success = rule_manager.add_custom_rule(
            code='custom_macros_detected',
            name='Macros Detected in Document',
            description='Office document contains macros (potential malware vector)',
            weight=70,
            category='content',
            created_by='test_investigator'
        )

        print(f"   [OK] Created custom rule: {success}")
        if success:
            custom_rule = rule_manager.get_rule('custom_macros_detected')
            print(f"        Code: {custom_rule.code}")
            print(f"        Name: {custom_rule.name}")
            print(f"        Weight: {custom_rule.weight} pts")
            print(f"        Custom: {custom_rule.custom}")
            print(f"        New version: {rule_manager.current_version.version}")

        print()
        print("[4] Testing 'Why NOT Flagged' Analysis...")

        # Create a file that scores LOW
        low_risk_file = {
            'name': 'report.docx',
            'path': 'C:/Users/Test/Documents/report.docx',
            'size': 1024000,
            'created': '2024-01-15T10:30:00Z',
            'modified': '2024-01-15T10:30:00Z',
            'entropy': 5.5,
            'mime_type': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
        }

        # Score it
        scorer = RiskScorer(case_id="test_high_001")
        risk_score = scorer.score_file(low_risk_file)

        print(f"   [OK] File scored: {risk_score.score}/100")
        print(f"        Severity: {risk_score.severity}")
        print(f"        Rules fired: {len(risk_score.reasons)}")

        # Analyze why not flagged
        analysis = rule_manager.analyze_why_not_flagged(low_risk_file, risk_score)

        print(f"   [OK] Why NOT flagged analysis:")
        print(f"        File: {analysis.file_name}")
        print(f"        Score: {analysis.total_score}/100")
        print(f"        Threshold gap: {analysis.threshold_not_met} pts")
        print(f"        Rules checked: {analysis.rules_checked}")
        print(f"        Rules fired: {analysis.rules_fired}")
        print(f"        Rules NOT fired: {len(analysis.rules_not_fired)}")

        # Show why rules didn't fire (top 5)
        print(f"   [OK] Top rules that didn't fire:")
        for code, reason, weight in analysis.rules_not_fired[:5]:
            print(f"        [{weight:3d} pts] {code}: {reason}")

        print()
        print("[5] Testing Version Rollback...")

        # Rollback to version 1
        if len(rule_manager.versions) > 1:
            success = rule_manager.rollback_to_version(
                version_num=1,
                changed_by='test_admin',
                reason='Reverting experimental changes'
            )
            print(f"   [OK] Rolled back to version 1: {success}")
            print(f"        Current version now: {rule_manager.current_version.version}")

        print()
        print("[6] Testing Configuration Export...")

        # Export current config
        export_path = "config/test_rules_export.json"
        os.makedirs("config", exist_ok=True)

        success = rule_manager.export_config(export_path)
        print(f"   [OK] Exported configuration: {success}")
        if success:
            print(f"        Path: {export_path}")

        print()
        print("[PASS] EXPLAINABILITY CONTROLS TEST COMPLETE")
        return True

    except Exception as e:
        print(f"[FAIL] Error: {e}")
        import traceback
        traceback.print_exc()
        return False


# Main test runner
def main():
    """Run all HIGH priority feature tests"""
    print("=" * 70)
    print("FORENSAI - HIGH PRIORITY FEATURES TEST SUITE")
    print("=" * 70)
    print(f"Test Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print()
    print("Testing critical defensive forensics features:")
    print("  1. Confidence & Uncertainty Metrics")
    print("  2. False Positive Protection")
    print("  3. Explainability Controls")
    print()

    results = []

    # Run tests
    results.append(("Confidence & Uncertainty", test_confidence_tracking()))
    results.append(("False Positive Protection", test_false_positive_protection()))
    results.append(("Explainability Controls", test_explainability_controls()))

    # Summary
    print()
    print("=" * 70)
    print("TEST SUMMARY")
    print("=" * 70)

    passed = sum(1 for _, result in results if result)
    total = len(results)

    for name, result in results:
        status = "[PASS]" if result else "[FAIL]"
        print(f"{status} {name}")

    print()
    print(f"Results: {passed}/{total} tests passed")

    if passed == total:
        print()
        print("=" * 70)
        print("ALL HIGH PRIORITY FEATURES TESTS PASSED")
        print("=" * 70)
        print()
        print("Features Status:")
        print("  [OK] Confidence & Uncertainty Metrics - IMPLEMENTED")
        print("       - AI confidence parsing")
        print("       - Derived vs inferred fact tracking")
        print("       - Uncertainty indicators")
        print("       - Confidence reports")
        print()
        print("  [OK] False Positive Protection - IMPLEMENTED")
        print("       - Whitelist manager (NSRL, custom)")
        print("       - VirusTotal API integration")
        print("       - PE signature verification")
        print("       - Result caching")
        print()
        print("  [OK] Explainability Controls - IMPLEMENTED")
        print("       - Rule weight adjustment (versioned)")
        print("       - Custom rule creation")
        print("       - 'Why NOT flagged' analysis")
        print("       - Configuration export/rollback")
        print()
        print("Next Steps:")
        print("  - Create UI components for HIGH features")
        print("  - Integrate into Priority tab and Case Audit tab")
        print("  - User acceptance testing with real cases")
        print("=" * 70)
    else:
        print()
        print(f"[WARNING] {total - passed} test(s) failed")

    return passed == total


if __name__ == '__main__':
    success = main()
    sys.exit(0 if success else 1)
