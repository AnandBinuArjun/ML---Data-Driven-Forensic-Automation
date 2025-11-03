import subprocess
import json
import os
from typing import Dict, List, Optional

class VolatilityIntegration:
    """
    Integration with Volatility 3 for memory forensic analysis
    """
    
    def __init__(self, volatility_path: str = "vol.py"):
        self.volatility_path = volatility_path
    
    def run_plugin(self, plugin_name: str, memory_image: str, 
                   output_format: str = "json", additional_args: Optional[List[str]] = None) -> Dict:
        """
        Run a Volatility 3 plugin on a memory image
        
        Args:
            plugin_name: Name of the Volatility plugin to run
            memory_image: Path to the memory image file
            output_format: Output format (json, csv, etc.)
            additional_args: Additional arguments for the plugin
            
        Returns:
            Dictionary containing the plugin output
        """
        # Build the command
        cmd = [
            self.volatility_path,
            "-f", memory_image,
            plugin_name,
            "--output-format", output_format
        ]
        
        if additional_args:
            cmd.extend(additional_args)
        
        print(f"Running Volatility command: {' '.join(cmd)}")
        
        try:
            # Run the command
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            
            if output_format == "json":
                return json.loads(result.stdout)
            else:
                return {"output": result.stdout}
                
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
    Example usage of the VolatilityIntegration class
    """
    # Initialize the integration
    vol = VolatilityIntegration()
    
    # Example: List processes in a memory image
    # memory_image = "example_memory.dmp"
    # result = vol.pslist(memory_image)
    # print(json.dumps(result, indent=2))

if __name__ == "__main__":
    main()