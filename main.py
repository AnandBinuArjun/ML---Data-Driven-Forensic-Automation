"""
Main entry point for the ML & Data-Driven Forensic Automation project
"""
import argparse
import sys
import os

# Add src directory to Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

def main():
    """
    Dispatcher for the ML & Data-Driven Forensic Automation Toolkit
    """
    if len(sys.argv) < 2:
        print("ML & Data-Driven Forensic Automation Toolkit")
        print("============================================")
        print("Available modules:")
        print("  network-analyzer    Analyze network traffic for malicious patterns")
        print("  volatility-int      Integrate with Volatility 3 for memory forensics")
        print("  case-pipeline       Handle CASE-compliant forensic data")
        print("\nUse 'python main.py [module] --help' for more information.")
        return

    module = sys.argv[1]
    
    if module == "network-analyzer":
        from src.tools.network_traffic_analyzer import main as network_main
        sys.argv = [sys.argv[0]] + sys.argv[2:]
        network_main()
        
    elif module == "volatility-int":
        from src.utils.volatility_integration import main as volatility_main
        sys.argv = [sys.argv[0]] + sys.argv[2:]
        volatility_main()
        
    elif module == "case-pipeline":
        from src.data.case_pipeline import main as case_main
        sys.argv = [sys.argv[0]] + sys.argv[2:]
        case_main()
        
    else:
        print(f"Unknown module: {module}")
        print("Available modules: network-analyzer, volatility-int, case-pipeline")

if __name__ == "__main__":
    main()