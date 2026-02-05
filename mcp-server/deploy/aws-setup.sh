#!/bin/bash
# InALign AWS EC2 Setup Script
# Run this on a fresh Amazon Linux 2023 or Ubuntu 22.04 instance

set -e

echo "=== InALign AWS Setup ==="

# Update system
echo "[1/5] Updating system..."
if command -v yum &> /dev/null; then
    sudo yum update -y
    sudo yum install -y docker git
elif command -v apt &> /dev/null; then
    sudo apt update && sudo apt upgrade -y
    sudo apt install -y docker.io docker-compose git
fi

# Start Docker
echo "[2/5] Starting Docker..."
sudo systemctl start docker
sudo systemctl enable docker
sudo usermod -aG docker $USER

# Clone repository
echo "[3/5] Cloning InALign..."
if [ ! -d "in-a-lign" ]; then
    git clone https://github.com/yourusername/in-a-lign.git
fi
cd in-a-lign/mcp-server

# Setup environment
echo "[4/5] Setting up environment..."
if [ ! -f "deploy/.env" ]; then
    cp deploy/.env.example deploy/.env
    echo ""
    echo ">>> IMPORTANT: Edit deploy/.env with your Neo4j Aura credentials"
    echo ">>> Run: nano deploy/.env"
    echo ""
fi

# Build and run
echo "[5/5] Building and starting..."
cd deploy
sudo docker compose up -d --build

echo ""
echo "=== Setup Complete ==="
echo "Dashboard: http://$(curl -s http://169.254.169.254/latest/meta-data/public-ipv4):8080"
echo ""
echo "To view logs: docker compose logs -f"
echo "To stop: docker compose down"
