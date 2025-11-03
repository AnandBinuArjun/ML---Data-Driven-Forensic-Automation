@echo off
echo Setting up ML & Data-Driven Forensic Automation project...
echo ======================================================

echo Installing required Python packages...
pip install -r requirements.txt

echo Creating sample dataset...
python -c "from examples.create_sample_data import create_sample_dataset; import pandas as pd; df = create_sample_dataset(); df.to_csv('sample_network_traffic.csv', index=False); print('Sample dataset saved to sample_network_traffic.csv')"

echo.
echo Setup completed successfully!
echo.
echo Next steps:
echo 1. Train the network traffic analyzer:
echo    python main.py network-analyzer --train sample_network_traffic.csv --save-model traffic_model.joblib
echo.
echo 2. Explore the demo notebook:
echo    jupyter notebook demo.ipynb
echo.
echo 3. Run tests:
echo    python -m pytest tests/
echo.
echo For more information, check the README.md file.
pause