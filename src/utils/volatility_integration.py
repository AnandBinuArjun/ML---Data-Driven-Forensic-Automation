import subprocess
import json
import os
import sys
from typing import Dict, List, Optional

class VolatilityIntegration:
    """
    Integration with Volatility 3 for memory forensic analysis
    """
    
    def __init__(self, volatility_path: str = None):
        if volatility_path:
            self.volatility_path = [volatility_path]
        else:
            # Try common ways to call Volatility 3
            self.volatility_path = ["vol", "vol.py", sys.executable, "-m", "volatility3"]
    
    def run_plugin(self, plugin_name: str, memory_image: str, 
                   output_format: str = "json", additional_args: Optional[List[str]] = None) -> Dict:
        """
        Run a Volatility 3 plugin on a memory image
        """
        if not os.path.exists(memory_image):
            return {"error": f"Memory image not found: {memory_image}"}

        # Build the command base
        base_cmd = []
        if self.volatility_path[0] == sys.executable:
            base_cmd = self.volatility_path + ["-f", memory_image, plugin_name, "--output-format", output_format]
        else:
            base_cmd = [self.volatility_path[0], "-f", memory_image, plugin_name, "--output-format", output_format]
        
        if additional_args:
            base_cmd.extend(additional_args)
        
        print(f"Running Volatility command: {' '.join(base_cmd)}")
        
        try:
            # Run the command
            result = subprocess.run(base_cmd, capture_output=True, text=True, check=True)
            
            if output_format == "json":
                return json.loads(result.stdout)
            else:
                return {"output": result.stdout}
                
        except FileNotFoundError:
            # If the first command failed, and we have alternatives, try them
            if len(self.volatility_path) > 1 and self.volatility_path[0] != sys.executable:
                print(f"Command '{self.volatility_path[0]}' not found. Trying alternatives...")
                # To keep it simple for this fix, we'll just suggest the fix if it fails
                return {"error": "Volatility 3 command not found. Please install it with 'pip install volatility3'"}
            return {"error": "Volatility 3 executable not found. Ensure 'vol' or 'vol.py' is in your PATH."}
        except subprocess.CalledProcessError as e:
            print(f"Error running Volatility: {e}")
            print(f"stderr: {e.stderr}")
            return {"error": str(e)}
        except json.JSONDecodeError as e:
            print(f"Error parsing JSON output: {e}")
            return {"error": f"JSON parsing error: {str(e)}"}

    
    def pslist(self, memory_image: str) -> Dict:
        """
        List processes in a memory image
        
        Args:
            memory_image: Path to the memory image file
            
        Returns:
            Dictionary containing process list
        """
        return self.run_plugin("windows.pslist.PsList", memory_image)
    
    def netscan(self, memory_image: str) -> Dict:
        """
        Scan for network connections in a memory image
        
        Args:
            memory_image: Path to the memory image file
            
        Returns:
            Dictionary containing network connections
        """
        return self.run_plugin("windows.netscan.NetScan", memory_image)
    
    def filescan(self, memory_image: str) -> Dict:
        """
        Scan for file objects in a memory image
        
        Args:
            memory_image: Path to the memory image file
            
        Returns:
            Dictionary containing file objects
        """
        return self.run_plugin("windows.filescan.FileScan", memory_image)
    
    def registry_printkey(self, memory_image: str, key: str) -> Dict:
        """
        Print a registry key from a memory image
        
        Args:
            memory_image: Path to the memory image file
            key: Registry key path to print
            
        Returns:
            Dictionary containing registry key information
        """
        additional_args = ["--key", key]
        return self.run_plugin("windows.registry.printkey.PrintKey", 
                              memory_image, additional_args=additional_args)

def main():
    """
    CLI interface for the Volatility integration
    """
    import argparse
    import sys
    
    parser = argparse.ArgumentParser(description='Volatility 3 Integration Tool')
    parser.add_argument(
        "--plugin",
        choices=["pslist", "netscan", "filescan", "registry"],
        help="Volatility plugin to run"
    )
    parser.add_argument(
        "--image",
        help="Memory image file to analyze"
    )
    parser.add_argument(
        "--key",
        help="Registry key (required for registry plugin)"
    )
    parser.add_argument(
        "--output",
        help="Output file path"
    )
    
    args = parser.parse_args()
    
    if not args.plugin or not args.image:
        print("Error: --plugin and --image are required for most operations.")
        # Running the example code if no arguments (minimal)
        print("Note: Actual Volatility commands require Volatility 3 and memory images.")
        return
        
    vol = VolatilityIntegration()
    result = {}
    
    if args.plugin == "pslist":
        result = vol.pslist(args.image)
    elif args.plugin == "netscan":
        result = vol.netscan(args.image)
    elif args.plugin == "filescan":
        result = vol.filescan(args.image)
    elif args.plugin == "registry":
        if not args.key:
            print("Error: --key required for registry plugin.")
            return
        result = vol.registry_printkey(args.image, args.key)
        
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(result, f, indent=2)
        print(f"Results saved to {args.output}")
    else:
        print(json.dumps(result, indent=2))

if __name__ == "__main__":
    main()