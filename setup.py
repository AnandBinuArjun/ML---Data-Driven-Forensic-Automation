#!/usr/bin/env python3
"""
Setup script for ML & Data-Driven Forensic Automation project
"""
import subprocess
import sys
import os

def install_requirements():
    """Install required Python packages"""
    print("Installing required Python packages...")
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"])
        print("Required packages installed successfully!")
        return True
    except subprocess.CalledProcessError as e:
        print(f"Error installing packages: {e}")
        return False

def create_sample_data():
    """Create sample dataset for demonstration"""
    print("Creating sample dataset...")
    try:
        # Add src to Python path
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))
        
        from examples.create_sample_data import create_sample_dataset
        import pandas as pd
        
        # Create sample dataset
        df = create_sample_dataset()
        
        # Save to CSV
        output_file = "sample_network_traffic.csv"
        df.to_csv(output_file, index=False)
        print(f"Sample dataset saved to {output_file}")
        return True
    except Exception as e:
        print(f"Error creating sample data: {e}")
        return False

def main():
    """Main setup function"""
    print("Setting up ML & Data-Driven Forensic Automation project...")
    print("=" * 50)
    
    # Install requirements
    if not install_requirements():
        print("Failed to install requirements. Please check your internet connection and try again.")
        return False
    
    # Create sample data
    if not create_sample_data():
        print("Failed to create sample data.")
        return False
    
    print("\nSetup completed successfully!")
    print("\nNext steps:")
    print("1. Train the network traffic analyzer:")
    print("   python main.py network-analyzer --train sample_network_traffic.csv --save-model traffic_model.joblib")
    print("\n2. Explore the demo notebook:")
    print("   jupyter notebook demo.ipynb")
    print("\n3. Run tests:")
    print("   python -m pytest tests/")
    
    return True

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)