import numpy as np
import pandas as pd
from scapy.all import *
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
import joblib
import argparse
import sys

class NetworkTrafficAnalyzer:
    """
    A Python implementation similar to FlowMeter for classifying network traffic
    as benign or malicious using machine learning techniques.
    """
    
    def __init__(self):
        self.model = None
        self.feature_names = [
            'packet_count', 'byte_count', 'duration', 
            'avg_packet_size', 'bytes_per_second',
            'packets_per_second', 'flow_duration'
        ]
        
    def extract_features(self, pcap_file):
        """
        Extract features from PCAP file for ML analysis
        """
        print(f"Extracting features from {pcap_file}")
        packets = rdpcap(pcap_file)
        
        # Initialize flow statistics
        packet_count = len(packets)
        byte_count = sum(len(packet) for packet in packets)
        
        if packet_count == 0:
            return None
            
        # Calculate timing features
        timestamps = [float(packet.time) for packet in packets if packet.haslayer(IP)]
        if len(timestamps) > 1:
            duration = max(timestamps) - min(timestamps)
        else:
            duration = 0
            
        # Calculate average packet size
        avg_packet_size = byte_count / packet_count if packet_count > 0 else 0
        
        # Calculate rate features
        bytes_per_second = byte_count / duration if duration > 0 else 0
        packets_per_second = packet_count / duration if duration > 0 else 0
        
        # Flow duration (simplified)
        flow_duration = duration
        
        features = [
            packet_count, byte_count, duration,
            avg_packet_size, bytes_per_second,
            packets_per_second, flow_duration
        ]
        
        return features
    
    def load_dataset(self, csv_file):
        """
        Load dataset from CSV file
        """
        print(f"Loading dataset from {csv_file}")
        df = pd.read_csv(csv_file)
        return df
    
    def train_model(self, X, y):
        """
        Train the Random Forest classifier
        """
        print("Training Random Forest classifier...")
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42
        )
        
        self.model = RandomForestClassifier(n_estimators=100, random_state=42)
        self.model.fit(X_train, y_train)
        
        # Evaluate model
        y_pred = self.model.predict(X_test)
        print("\nClassification Report:")
        print(classification_report(y_test, y_pred))
        
        return self.model
    
    def save_model(self, filepath):
        """
        Save trained model to disk
        """
        if self.model is not None:
            joblib.dump(self.model, filepath)
            print(f"Model saved to {filepath}")
        else:
            print("No model to save. Train a model first.")
    
    def load_model(self, filepath):
        """
        Load trained model from disk
        """
        self.model = joblib.load(filepath)
        print(f"Model loaded from {filepath}")
    
    def classify_traffic(self, features):
        """
        Classify traffic as benign (0) or malicious (1)
        """
        if self.model is None:
            raise ValueError("No model loaded. Train or load a model first.")
            
        features_array = np.array(features).reshape(1, -1)
        prediction = self.model.predict(features_array)
        probability = self.model.predict_proba(features_array)
        
        return prediction[0], probability[0]

def main():
    parser = argparse.ArgumentParser(description='Network Traffic Analyzer')
    parser.add_argument('--train', help='CSV file for training the model')
    parser.add_argument('--classify', help='PCAP file to classify')
    parser.add_argument('--model', help='Path to saved model file')
    parser.add_argument('--save-model', help='Path to save trained model')
    
    args = parser.parse_args()
    
    analyzer = NetworkTrafficAnalyzer()
    
    if args.train:
        # Train mode
        df = analyzer.load_dataset(args.train)
        X = df.drop('label', axis=1)  # Assuming 'label' column contains 0/1
        y = df['label']
        
        model = analyzer.train_model(X, y)
        
        if args.save_model:
            analyzer.save_model(args.save_model)
            
    elif args.classify:
        # Classification mode
        if args.model:
            analyzer.load_model(args.model)
        else:
            print("Error: --model argument required for classification")
            sys.exit(1)
            
        features = analyzer.extract_features(args.classify)
        if features is not None:
            prediction, probability = analyzer.classify_traffic(features)
            result = "Malicious" if prediction == 1 else "Benign"
            print(f"\nTraffic Classification: {result}")
            print(f"Confidence: {max(probability):.2f}")
        else:
            print("Could not extract features from the PCAP file")
    else:
        parser.print_help()

if __name__ == "__main__":
    main()