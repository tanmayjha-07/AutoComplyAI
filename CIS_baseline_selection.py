"""
cis_baseline_selector.py

Command-Line Interface (CLI) for selecting the compliance baseline (ISO, GDPR, or Mix) 
and executing the corresponding concurrent technical checks.
"""

import json
import os
import sys

# ==============================================================================
# IMPORT MODULES
# NOTE: This assumes all your checker files are in the same directory and accessible.
# In a production environment, you would handle import paths more robustly.
try:
    import windows_iso27001_check as iso_checker
    import windows_gdpr_check as gdpr_checker
    # Import supporting modules to access specific functions if needed for 'Mix'
    import windows_ac_check as wac
    import windows_patch_check as wpc
except ImportError as e:
    print(f"Error importing compliance modules: {e}")
    print("Please ensure all checker files (windows_iso27001_check.py, etc.) are in the Python path.")
    sys.exit(1)
# ==============================================================================


def run_checks(mode: str) -> Dict[str, Any]:
    """
    Executes the appropriate check based on the selected compliance mode.

    Args:
        mode: The selected compliance mode ('iso', 'gdpr', 'mix').

    Returns:
        A dictionary containing the results of the compliance check.
    """
    if mode == 'iso':
        print("\n⚙️ Executing ISO 27001 (Annex A) Technical Baseline Checks concurrently...")
        # Calls the concurrent ISO aggregation module
        return iso_checker.get_iso27001_technical_status()
        
    elif mode == 'gdpr':
        print("\n🛡️ Executing GDPR Technical Baseline Checks concurrently...")
        # Calls the concurrent GDPR aggregation module
        return gdpr_checker.get_gdpr_technical_status_modular()
        
    elif mode == 'mix':
        # Mix mode example: A combined report of high-level ISO and GDPR compliance status.
        print("\n🤝 Executing Mixed (ISO/GDPR) Baseline Checks concurrently...")
        
        # In the Mix mode, we call both aggregators and combine the results.
        # This leverages the concurrency built into each checker's main function.
        iso_results = iso_checker.get_iso27001_technical_status()
        gdpr_results = gdpr_checker.get_gdpr_technical_status_modular()
        
        return {
            "Compliance_Mode": "ISO 27001 & GDPR Mixed Baseline",
            "ISO_Annex_A_Report": iso_results,
            "GDPR_Articles_Report": gdpr_results,
            "Mix_Summary_Note": "The final compliance status is the intersection of both reports."
        }
        
    else:
        raise ValueError(f"Invalid mode selected: {mode}")


def main():
    """Main function to handle CLI interaction and output generation."""
    
    print("\n--- Compliance Baseline Selection (CIS Phase) ---")
    print("Select the desired compliance baseline:")
    print("  1. ISO 27001 (Technical Annex A Controls)")
    print("  2. GDPR (Technical Data Privacy Articles)")
    print("  3. Mix (Combined ISO 27001 & GDPR Report)")
    
    while True:
        choice = input("Enter choice (1/2/3): ").strip()
        
        if choice == '1':
            mode = 'iso'
            break
        elif choice == '2':
            mode = 'gdpr'
            break
        elif choice == '3':
            mode = 'mix'
            break
        else:
            print("Invalid selection. Please enter 1, 2, or 3.")

    try:
        results = run_checks(mode)
        
        # Final Output Formatting
        print("\n✅ Compliance Check Complete. Generating Report.")
        print("-" * 50)
        print(json.dumps(results, indent=2))
        print("-" * 50)

    except Exception as e:
        print(f"\n❌ A critical error occurred during execution: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()