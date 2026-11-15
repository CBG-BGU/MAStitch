"""
MAStitch Detection System - Main Testing Script

This script demonstrates MAStitch's anomaly detection capabilities across
different multi-agent applications with organized test cases.
"""

from typing import Dict, List, Tuple
import os
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

        # analyze_log_file returns a tuple; first item is True when an alert was raised
        result = int(analyze_log_file(test_case.log_path, config_path)[0])
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


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOGS = os.path.join(BASE_DIR, "example_logs")
CONFIGS = os.path.join(BASE_DIR, "configuration_files")


def trip_cases(d):
    """One benign log and one anomaly per attack scenario (DPI = direct prompt injection)"""
    attacks = (
        ("Misinformation", "DPI - misinformation injection"),
        ("Backdoor", "DPI - agent backdoor"),
        ("Exhaustion", "DPI - resource exhaustion"),
    )
    cases = [TestCase("Benign_Trip", os.path.join(d, "benign_log_Trip.json"), 0, "Normal travel planning")]
    for name, desc in attacks:
        cases.append(TestCase(f"Attack_DPI_{name}", os.path.join(d, f"anomaly_log_DPI_{name}.json"), 1, desc))
    return cases


def simple_app(app_name, folder, config_file, benign, anomaly, description):
    """Application with a single benign/anomaly log pair"""
    d = os.path.join(LOGS, folder)
    return ApplicationTest(
        app_name=app_name,
        config_path=os.path.join(CONFIGS, config_file),
        test_cases=[
            TestCase("Benign", os.path.join(d, benign), 0, "Normal operation"),
            TestCase("Attack", os.path.join(d, anomaly), 1, "Anomalous run"),
        ],
        description=description,
    )


def setup_trip_planner_crewai_tests() -> ApplicationTest:
    """Trip Planner (CrewAI): benign/anomaly pair per attack"""
    return ApplicationTest(
        app_name="Trip Planner (CrewAI)",
        config_path=os.path.join(CONFIGS, "TripPlanner_config_file.json"),
        test_cases=trip_cases(os.path.join(LOGS, "Trip_Planner_CrewAI")),
        description="CrewAI multi-agent travel planning with several attack vectors",
    )


def setup_instagram_tests() -> ApplicationTest:
    """Instagram Marketing System (CrewAI): one benign log, one indirect prompt injection (IPI) log"""
    d = os.path.join(LOGS, "Instagram_CrewAI")
    return ApplicationTest(
        app_name="Instagram Marketing (CrewAI)",
        config_path=os.path.join(CONFIGS, "Instagram_config_file.json"),
        test_cases=[
            TestCase("Benign_Instagram", os.path.join(d, "benign_log_Instagram.json"), 0,
                     "Normal Instagram ad-campaign run"),
            TestCase("Attack_IPI", os.path.join(d, "anomaly_log_IPI.json"), 1,
                     "Indirect prompt injection (IPI)"),
            TestCase("Benign_Instagram_val", os.path.join(d, "benign_log_Instagram_val.json"), 0,
                     "Normal Instagram ad-campaign run"),
            TestCase("Attack_Instagram_val", os.path.join(d, "anomaly_log_Instagram_val.json"), 1,
                     "Anomalous run"),
        ],
        description="CrewAI multi-agent Instagram marketing system",
    )


def setup_trip_planner_tests() -> ApplicationTest:
    """Trip Planner (LangGraph): one benign log, three direct prompt injection (DPI) logs"""
    d = os.path.join(LOGS, "Trip_Planner_LangGraph")
    return ApplicationTest(
        app_name="Trip Planner (LangGraph)",
        config_path=os.path.join(CONFIGS, "TripPlanner_LangGraph_config_file.json"),
        test_cases=trip_cases(d),
        description="LangGraph multi-agent travel planning with several attack vectors",
    )


def main():
    """Main execution function"""

    # Initialize tester
    tester = MAStitchTester()

    # Add application test suites
    print("Setting up test suites...")

    # Instagram Marketing (CrewAI)
    tester.add_application(setup_instagram_tests())

    # Trip Planner (LangGraph) - Multiple attack types
    tester.add_application(setup_trip_planner_tests())

    # Trip Planner (CrewAI) - Multiple attack types
    tester.add_application(setup_trip_planner_crewai_tests())

    tester.add_application(simple_app(
        "Game Builder (CrewAI)", "GameBuilder", "GameBuilder_config_file.json",
        "benign_log_GameBuilder.json", "anomaly_log_GameBuilder.json", "CrewAI game builder"))
    tester.add_application(simple_app(
        "GenFIC Stories Generator (LangGraph)", "Genfic", "GenFIC_config_file.json",
        "benign_log_Genfic.json", "anomaly_log_Genfic.json", "LangGraph story generator"))
    tester.add_application(simple_app(
        "Real Estate (CrewAI)", "RealEstate", "RealEstate_config_file.json",
        "benign_log_RealEstate.json", "anomaly_log_RealEstate.json", "CrewAI real estate"))

    # Run all tests
    tester.run_all()


if __name__ == "__main__":
    main()
