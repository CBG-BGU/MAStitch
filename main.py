"""
MAStitch Detection System - Main Testing Script

This script demonstrates MAStitch's anomaly detection capabilities across
different multi-agent applications with organized test cases.
"""

from typing import Dict, List, Tuple
from dataclasses import dataclass
from MAStitch_detection import analyze_log_file


@dataclass
class TestCase:
    """Represents a single test case with an expected outcome"""
    name: str
    log_path: str
    expected: int  # 0 for benign, 1 for alert
    description: str = ""


@dataclass
class ApplicationTest:
    """Collection of test cases for a specific application"""
    app_name: str
    config_path: str
    test_cases: List[TestCase]
    description: str = ""


class MAStitchTester:
    """Organizes and runs MAStitch detection tests across applications"""

    def __init__(self):
        self.applications: List[ApplicationTest] = []
        self.results: Dict[str, List[Tuple[str, int, int, bool]]] = {}

    def add_application(self, app_test: ApplicationTest):
        """Add an application test suite"""
        self.applications.append(app_test)

    def run_test(self, test_case: TestCase, config_path: str, app_name: str) -> Tuple[int, bool]:
        """Run a single test case"""
        print(f"\n{'=' * 80}")
        print(f"Testing: {app_name} - {test_case.name}")
        if test_case.description:
            print(f"Description: {test_case.description}")
        print(f"Expected: {'ALERT' if test_case.expected == 1 else 'BENIGN'}")
        print(f"{'=' * 80}")

        result = analyze_log_file(test_case.log_path, config_path)
        print(f"Result: {result}")
        passed = (result == test_case.expected)

        return result, passed

    def run_application_tests(self, app_test: ApplicationTest):
        """Run all tests for a specific application"""
        print(f"\n\n{'#' * 80}")
        print(f"# APPLICATION: {app_test.app_name}")
        if app_test.description:
            print(f"# {app_test.description}")
        print(f"{'#' * 80}")

        app_results = []

        for test_case in app_test.test_cases:
            try:
                result, passed = self.run_test(test_case, app_test.config_path, app_test.app_name)
                app_results.append((test_case.name, test_case.expected, result, passed))

                # Print immediate result
                status = "✅ PASS" if passed else "❌ FAIL"
                print(f"\n{status}: Expected {test_case.expected}, Got {result}")

            except Exception as e:
                print(f"\n❌ ERROR: {test_case.name} failed with exception: {e}")
                app_results.append((test_case.name, test_case.expected, -1, False))

        self.results[app_test.app_name] = app_results

    def run_all(self):
        """Run all registered application tests"""
        print("\n" + "=" * 80)
        print("MAStitch Detection System - Test Suite")
        print("=" * 80)
        print(f"Total Applications: {len(self.applications)}")
        print(f"Total Test Cases: {sum(len(app.test_cases) for app in self.applications)}")

        for app_test in self.applications:
            self.run_application_tests(app_test)

        self.print_summary()

    def print_summary(self):
        """Print overall test summary"""
        print(f"\n\n{'=' * 80}")
        print("FINAL TEST SUMMARY")
        print(f"{'=' * 80}\n")

        total_tests = 0
        total_passed = 0

        for app_name, results in self.results.items():
            print(f"\n{app_name}:")
            print("-" * 60)

            app_passed = sum(1 for _, _, _, passed in results if passed)
            app_total = len(results)

            for test_name, expected, result, passed in results:
                status = "✅" if passed else "❌"
                print(f"  {status} {test_name:<40} Expected: {expected}, Got: {result}")

            print(f"\n  Application Score: {app_passed}/{app_total} " +
                  f"({100 * app_passed / app_total if app_total > 0 else 0:.1f}%)")

            total_tests += app_total
            total_passed += app_passed

        print(f"\n{'=' * 80}")
        print(f"OVERALL SCORE: {total_passed}/{total_tests} " +
              f"({100 * total_passed / total_tests if total_tests > 0 else 0:.1f}%)")
        print(f"{'=' * 80}\n")


def setup_supervisor_tests() -> ApplicationTest:
    """Configure test cases for PDF Scholar Supervisor application"""

    base_dir = "example_logs"  # Modify
    config_path = "configuration_files/PdfScholar_Supervisor_config_file.json"

    test_cases = [
        # Benign Cases
        TestCase(
            name="Benign_01",
            log_path=f"{base_dir}/telemetry_0929d94d-e160-4ae2-a59a-91f0a0d5746f_1764333524.json",
            expected=0,
            description="Normal PDF processing and search operations"
        ),

        # Attack Cases
        TestCase(
            name="Attack_01",
            log_path=f"{base_dir}/telemetry_15c2ed89-586f-4eb3-955f-48f13fa6e6f7_1764185629.json",
            expected=1,
            description="Malicious behavior - should trigger alert"
        ),
    ]

    return ApplicationTest(
        app_name="PDF Scholar Supervisor",
        config_path=config_path,
        test_cases=test_cases,
        description="LangGraph supervisor pattern with PDF processing agents"
    )


def setup_trip_planner_tests() -> ApplicationTest:
    """Configure test cases for Trip Planner application (CrewAI)"""

    base_dir = "example_logs"  # Modify
    config_path = "configuration_files/TripPlanner_config_file.json"

    test_cases = [
        # Misinformation Attack
        TestCase(
            name="Benign_Cafe",
            log_path=f"{base_dir}/telemetry_data20250410_163705.json",
            expected=0,
            description="Normal travel planning"
        ),
        TestCase(
            name="Attack_Misinformation",
            log_path=f"{base_dir}/telemetry_data20250417_104459.json",
            expected=1,
            description="Cafe misinformation injection"
        ),

        # PARS Attack
        TestCase(
            name="Benign_PARS",
            log_path=f"{base_dir}/telemetry_data20250410_164310.json",
            expected=0,
            description="Normal travel planning"
        ),
        TestCase(
            name="Attack_PARS",
            log_path=f"{base_dir}/telemetry_data20250417_193735.json",
            expected=1,
            description="PARS prompt injection attack"
        ),

        # Backdoor Attack
        TestCase(
            name="Benign_Backdoor",
            log_path=f"{base_dir}/telemetry_data20250410_181319.json",
            expected=0,
            description="Normal travel planning"
        ),
        TestCase(
            name="Attack_Backdoor",
            log_path=f"{base_dir}/telemetry_data20250417_224826.json",
            expected=1,
            description="Agent backdoor compromise"
        ),
    ]

    return ApplicationTest(
        app_name="Trip Planner (CrewAI)",
        config_path=config_path,
        test_cases=test_cases,
        description="Multi-agent travel planning with various attack vectors"
    )


def main():
    """Main execution function"""

    # Initialize tester
    tester = MAStitchTester()

    # Add application test suites
    print("Setting up test suites...")

    # PDF Scholar Supervisor (LangGraph)
    tester.add_application(setup_supervisor_tests())

    # Trip Planner (CrewAI) - Multiple attack types
    tester.add_application(setup_trip_planner_tests())

    # Run all tests
    tester.run_all()


if __name__ == "__main__":
    main()
