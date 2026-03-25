"""
Example script demonstrating the network traffic analyzer
"""
import pandas as pd
import numpy as np
import os

def create_sample_dataset():
    """
    Create a sample dataset for training the network traffic analyzer
    """
    # Create sample data with features similar to what the analyzer expects
    np.random.seed(42)
    
    # Generate benign traffic samples
    benign_samples = 1000
    benign_data = {
        'packet_count': np.random.normal(500, 100, benign_samples),
        'byte_count': np.random.normal(50000, 10000, benign_samples),
        'duration': np.random.exponential(30, benign_samples),
        'avg_packet_size': np.random.normal(1000, 200, benign_samples),
        'bytes_per_second': np.random.normal(2000, 500, benign_samples),
        'packets_per_second': np.random.normal(20, 5, benign_samples),
        'flow_duration': np.random.exponential(60, benign_samples),
        'label': [0] * benign_samples  # 0 for benign
    }
    
    # Generate malicious traffic samples
    malicious_samples = 300
    malicious_data = {
        'packet_count': np.random.normal(2000, 500, malicious_samples),
        'byte_count': np.random.normal(200000, 50000, malicious_samples),
        'duration': np.random.exponential(120, malicious_samples),
        'avg_packet_size': np.random.normal(800, 150, malicious_samples),
        'bytes_per_second': np.random.normal(5000, 1000, malicious_samples),
        'packets_per_second': np.random.normal(50, 15, malicious_samples),
        'flow_duration': np.random.exponential(300, malicious_samples),
        'label': [1] * malicious_samples  # 1 for malicious
    }
    
    # Combine datasets
    combined_data = {}
    for key in benign_data.keys():
        combined_data[key] = list(benign_data[key]) + list(malicious_data[key])
    
    # Create DataFrame
    df = pd.DataFrame(combined_data)
    
    # Ensure no negative values
    numeric_columns = ['packet_count', 'byte_count', 'duration', 'avg_packet_size', 
                      'bytes_per_second', 'packets_per_second', 'flow_duration']
    for col in numeric_columns:
        df[col] = np.abs(df[col])
    
    return df

def main():
    """
    Create sample dataset and save to CSV
    """
    print("Creating sample network traffic dataset...")
    
    # Create sample dataset
    df = create_sample_dataset()
    
    # Save to CSV
    output_file = "sample_network_traffic.csv"
    df.to_csv(output_file, index=False)
    print(f"Sample dataset saved to {output_file}")
    
    # Show dataset info
    print(f"\nDataset shape: {df.shape}")
    print(f"Benign samples (0): {len(df[df['label'] == 0])}")
    print(f"Malicious samples (1): {len(df[df['label'] == 1])}")
    print("\nFirst few rows:")
    print(df.head())
    
    print("\nTo train the network traffic analyzer with this data:")
    print(f"python main.py network-analyzer --train {output_file} --save-model traffic_model.joblib")
    
    print("\nTo classify a PCAP file with the trained model:")
    print("python main.py network-analyzer --classify sample.pcap --model traffic_model.joblib")

if __name__ == "__main__":
    main()