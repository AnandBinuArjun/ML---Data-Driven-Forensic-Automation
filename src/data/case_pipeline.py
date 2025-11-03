import json
import hashlib
from typing import Dict, List, Any, Optional
from datetime import datetime

class CASEDataPipeline:
    """
    Data pipeline for handling CASE (Cyber-investigation Analysis Standard Expression) 
    compliant forensic data.
    """
    
    def __init__(self):
        self.case_data = {
            "@context": {
                "case": "http://case.example.org/core",
                "rdf": "http://www.w3.org/1999/02/22-rdf-syntax-ns#",
                "rdfs": "http://www.w3.org/2000/01/rdf-schema#",
                "xsd": "http://www.w3.org/2001/XMLSchema#"
            },
            "@graph": []
        }
        
    def add_investigation(self, investigation_id: str, title: str, 
                         description: str, start_date: Optional[str] = None) -> str:
        """
        Add an investigation to the CASE data
        
        Args:
            investigation_id: Unique identifier for the investigation
            title: Title of the investigation
            description: Description of the investigation
            start_date: Start date of investigation (ISO format)
            
        Returns:
            Investigation identifier
        """
        if not start_date:
            start_date = datetime.now().isoformat()
            
        investigation = {
            "@id": f"investigation:{investigation_id}",
            "@type": "case:Investigation",
            "case:title": title,
            "case:description": description,
            "case:startTime": start_date
        }
        
        self.case_data["@graph"].append(investigation)
        return investigation["@id"]
    
    def add_evidence(self, evidence_id: str, investigation_id: str,
                    file_path: str, description: Optional[str] = None) -> str:
        """
        Add evidence to the CASE data
        
        Args:
            evidence_id: Unique identifier for the evidence
            investigation_id: Identifier of the investigation
            file_path: Path to the evidence file
            description: Description of the evidence
            
        Returns:
            Evidence identifier
        """
        # Calculate file hash
        file_hash = self._calculate_file_hash(file_path)
        
        evidence = {
            "@id": f"evidence:{evidence_id}",
            "@type": "case:File",
            "case:filePath": file_path,
            "case:hash": file_hash,
            "case:description": description or f"Evidence file: {file_path}"
        }
        
        self.case_data["@graph"].append(evidence)
        
        # Link evidence to investigation
        relationship = {
            "@id": f"relationship:{investigation_id}-{evidence_id}",
            "@type": "case:Relationship",
            "case:source": f"investigation:{investigation_id}",
            "case:target": f"evidence:{evidence_id}",
            "case:relationshipKind": "investigates"
        }
        
        self.case_data["@graph"].append(relationship)
        return evidence["@id"]
    
    def add_observable(self, observable_id: str, evidence_id: str,
                      observable_type: str, value: str, description: Optional[str] = None) -> str:
        """
        Add an observable to the CASE data
        
        Args:
            observable_id: Unique identifier for the observable
            evidence_id: Identifier of the evidence
            observable_type: Type of observable (IP, Domain, Hash, etc.)
            value: Value of the observable
            description: Description of the observable
            
        Returns:
            Observable identifier
        """
        observable = {
            "@id": f"observable:{observable_id}",
            "@type": "case:ObservableObject",
            "case:observableType": observable_type,
            "case:value": value,
            "case:description": description or f"{observable_type}: {value}"
        }
        
        self.case_data["@graph"].append(observable)
        
        # Link observable to evidence
        relationship = {
            "@id": f"relationship:{evidence_id}-{observable_id}",
            "@type": "case:Relationship",
            "case:source": f"evidence:{evidence_id}",
            "case:target": f"observable:{observable_id}",
            "case:relationshipKind": "contains"
        }
        
        self.case_data["@graph"].append(relationship)
        return observable["@id"]
    
    def _calculate_file_hash(self, file_path: str) -> str:
        """
        Calculate SHA256 hash of a file
        
        Args:
            file_path: Path to the file
            
        Returns:
            SHA256 hash of the file
        """
        sha256_hash = hashlib.sha256()
        try:
            with open(file_path, "rb") as f:
                # Read and update hash string value in blocks of 4K
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except FileNotFoundError:
            return "File not found"
    
    def save_to_json(self, file_path: str):
        """
        Save CASE data to JSON file
        
        Args:
            file_path: Path to save the JSON file
        """
        with open(file_path, 'w') as f:
            json.dump(self.case_data, f, indent=2)
        print(f"CASE data saved to {file_path}")
    
    def load_from_json(self, file_path: str):
        """
        Load CASE data from JSON file
        
        Args:
            file_path: Path to the JSON file
        """
        with open(file_path, 'r') as f:
            self.case_data = json.load(f)
        print(f"CASE data loaded from {file_path}")
    
    def to_dataframe(self):
        """
        Convert CASE data to pandas DataFrame for ML processing
        
        Returns:
            DataFrame containing the CASE data or raw data if pandas is not available
        """
        try:
            import pandas as pd
            records = []
            
            # Extract relevant information from the graph
            for item in self.case_data["@graph"]:
                record = {
                    "id": item.get("@id", ""),
                    "type": item.get("@type", ""),
                    "description": item.get("case:description", ""),
                    "value": item.get("case:value", ""),
                    "file_path": item.get("case:filePath", ""),
                    "hash": item.get("case:hash", ""),
                    "observable_type": item.get("case:observableType", "")
                }
                records.append(record)
                
            return pd.DataFrame(records)
        except ImportError:
            print("Pandas not available. Returning raw data instead.")
            return self.case_data
    
    def get_evidence_files(self) -> List[str]:
        """
        Get list of evidence file paths
        
        Returns:
            List of evidence file paths
        """
        evidence_files = []
        for item in self.case_data["@graph"]:
            if item.get("@type") == "case:File" and "case:filePath" in item:
                evidence_files.append(item["case:filePath"])
        return evidence_files

def main():
    """
    Example usage of the CASEDataPipeline class
    """
    # Initialize the pipeline
    pipeline = CASEDataPipeline()
    
    # Add an investigation
    inv_id = pipeline.add_investigation(
        "inv_001", 
        "Suspicious Network Activity", 
        "Investigation of potential APT activity"
    )
    
    # Add evidence (in a real scenario, this would be actual evidence files)
    # evidence_id = pipeline.add_evidence(
    #     "ev_001", 
    #     inv_id, 
    #     "/path/to/evidence.pcap", 
    #     "Network capture file"
    # )
    
    # Save to JSON
    # pipeline.save_to_json("case_data.json")

if __name__ == "__main__":
    main()