# ML & Data-Driven Forensic Automation

This project provides a comprehensive toolkit for applying Machine Learning and Data-Driven approaches to digital forensics and cyber security investigations. Developed by Anand Binu Arjun as part of Cluster 2 research on AI/ML applications in digital forensics.

## Features

### 1. Network Traffic Analyzer
- ML-based classification of network traffic as benign or malicious
- Feature extraction from PCAP files
- Random Forest classifier with model persistence
- Command-line interface for training and classification

### 2. Volatility 3 Integration
- Memory forensic analysis capabilities
- Process listing, network connection scanning, file scanning
- Registry analysis with JSON output support
- Extensible plugin architecture

### 3. CASE Data Pipeline
- CASE (Cyber-investigation Analysis Standard Expression) compliant forensic data handling
- Investigation and evidence management
- Observable collection and tracking
- JSON data export for interoperability

## Installation

1. Clone the repository:
   ```bash
   git clone <repository-url>
   cd ml-data-driven-forensic-automation
   ```

2. Install the required dependencies:
   ```bash
   pip install -r requirements.txt
   ```
   
   On Windows systems with permission restrictions:
   ```bash
   pip install --user -r requirements.txt
   ```

## Usage

The project can be used through the main entry point:

```bash
python main.py [module] [options]
```

### Network Traffic Analyzer

Train a model with sample data:
```bash
python main.py network-analyzer --train sample_network_traffic.csv --save-model traffic_model.joblib
```

Classify a PCAP file:
```bash
python main.py network-analyzer --classify sample.pcap --model traffic_model.joblib
```

### Volatility Integration

Analyze a memory image:
```bash
python main.py volatility-int --plugin pslist --image memory.dmp
```

Available plugins:
- `pslist`: List processes
- `netscan`: Scan network connections
- `filescan`: Scan file objects
- `registry`: Analyze registry keys

### CASE Pipeline

Create and manage forensic investigations:
```
python main.py case-pipeline --create-investigation inv_001 "Network Investigation" "Suspicious activity"
python main.py case-pipeline --add-evidence ev_001 inv_001 /path/to/evidence.pcap
python main.py case-pipeline --save case_data.json
```

## Project Structure

```
ml-data-driven-forensic-automation/
├── src/
│   ├── data/
│   │   └── case_pipeline.py          # CASE-compliant data handling
│   ├── tools/
│   │   └── network_traffic_analyzer.py  # Network traffic classification
│   └── utils/
│       └── volatility_integration.py  # Volatility 3 integration
├── examples/
│   └── create_sample_data.py         # Sample data generator
├── tests/
│   └── test_toolkit.py               # Test suite
├── main.py                           # Main entry point
├── requirements.txt                  # Python dependencies
├── demo.ipynb                        # Jupyter notebook demo
├── sample_network_traffic.csv        # Sample dataset
└── traffic_model.joblib             # Trained ML model
```

## Google Colab Integration

The project supports Google Colab for cloud-based experimentation. The [demo.ipynb](file:///c%3A/Users/anand/Downloads/ML%20%26%20DATA%20DRIVEN%20FORENSIC%20AUTOMOTATION/demo.ipynb) notebook provides examples of how to use all components in a cloud environment.

## Requirements

- Python 3.7+
- NumPy
- Pandas
- Scikit-learn
- Scapy
- Matplotlib
- Seaborn
- Joblib
- Volatility 3 (for memory forensics)

## Creator

**Anand Binu Arjun** - *Initial work* - [Your GitHub Profile]

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Based on research from Cluster 2: Machine Learning and Data-Driven Forensic Automation
- Inspired by the AI4DigitalForensics repository
- Utilizes FlowMeter concepts for network traffic classification
- Integrates with Volatility 3 for memory forensics
- Implements CASE standards for forensic data interoperability