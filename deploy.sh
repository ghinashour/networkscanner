#!/bin/bash
# Deployment script

echo "🚀 Deploying Network Scanner..."

# Install dependencies
pip install -r requirements.txt

# Initialize database
python -c "from scripts.cve_integration import CVEService; CVEService()"

# Start application
python app.py

echo "✅ Deployment complete!"