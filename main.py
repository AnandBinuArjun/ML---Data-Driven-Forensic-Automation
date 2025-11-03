"""
Main entry point for the ML & Data-Driven Forensic Automation project
"""
import argparse
import sys
import os

# Add src directory to Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

def main():
    parser = argparse.ArgumentParser(
        description="ML & Data-Driven Forensic Automation Toolkit",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Available modules:
  network-analyzer    Analyze network traffic for malicious patterns
  volatility-int      Integrate with Volatility 3 for memory forensics
  case-pipeline       Handle CASE-compliant forensic data
  
Examples:
  python main.py network-analyzer --help
  python main.py volatility-int --help
  python main.py case-pipeline --help
        """
    )
    
    subparsers = parser.add_subparsers(
        dest="module",
        help="Select which module to use"
    )
    
    # Network Analyzer Module
    network_parser = subparsers.add_parser(
        "network-analyzer",
        help="Analyze network traffic using ML techniques"
    )
    network_parser.add_argument(
        "--train",
        help="CSV file for training the model"
    )
    network_parser.add_argument(
        "--classify",
        help="PCAP file to classify"
    )
    network_parser.add_argument(
        "--model",
        help="Path to saved model file"
    )
    network_parser.add_argument(
        "--save-model",
        help="Path to save trained model"
    )
    
    # Volatility Integration Module
    vol_parser = subparsers.add_parser(
        "volatility-int",
        help="Integrate with Volatility 3 for memory forensics"
    )
    vol_parser.add_argument(
        "--plugin",
        choices=["pslist", "netscan", "filescan", "registry"],
        help="Volatility plugin to run"
    )
    vol_parser.add_argument(
        "--image",
        help="Memory image file to analyze"
    )
    vol_parser.add_argument(
        "--key",
        help="Registry key (required for registry plugin)"
    )
    vol_parser.add_argument(
        "--output",
        help="Output file path"
    )
    
    # CASE Pipeline Module
    case_parser = subparsers.add_parser(
        "case-pipeline",
        help="Handle CASE-compliant forensic data"
    )
    case_parser.add_argument(
        "--create-investigation",
        nargs=3,
        metavar=("ID", "TITLE", "DESCRIPTION"),
        help="Create a new investigation"
    )
    case_parser.add_argument(
        "--add-evidence",
        nargs=3,
        metavar=("EVIDENCE_ID", "INVESTIGATION_ID", "FILE_PATH"),
        help="Add evidence to an investigation"
    )
    case_parser.add_argument(
        "--add-observable",
        nargs=4,
        metavar=("OBSERVABLE_ID", "EVIDENCE_ID", "TYPE", "VALUE"),
        help="Add observable to evidence"
    )
    case_parser.add_argument(
        "--save",
        help="Save CASE data to JSON file"
    )
    
    args = parser.parse_args()
    
    if args.module == "network-analyzer":
        from src.tools.network_traffic_analyzer import main as network_main
        # Pass the arguments to the network analyzer
        sys.argv = [sys.argv[0]] + sys.argv[2:]  # Remove the module argument
        network_main()
        
    elif args.module == "volatility-int":
        from src.utils.volatility_integration import main as volatility_main
        # Pass the arguments to the volatility integration
        sys.argv = [sys.argv[0]] + sys.argv[2:]  # Remove the module argument
        volatility_main()
        
    elif args.module == "case-pipeline":
        from src.data.case_pipeline import main as case_main
        # Pass the arguments to the CASE pipeline
        sys.argv = [sys.argv[0]] + sys.argv[2:]  # Remove the module argument
        case_main()
        
    else:
        parser.print_help()

if __name__ == "__main__":
    main()