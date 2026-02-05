#!/bin/bash
# InALign EC2 User Data Script

# Log everything
exec > >(tee /var/log/inalign-setup.log) 2>&1

echo "=== InALign Setup Started ==="

# Install Docker
yum update -y
yum install -y docker git
systemctl start docker
systemctl enable docker

# Clone repo
cd /home/ec2-user
git clone https://github.com/Intellirim/ontix-aisecurity.git in-a-lign
chown -R ec2-user:ec2-user in-a-lign

# Build image
cd /home/ec2-user/in-a-lign/mcp-server
docker build -f deploy/Dockerfile.simple -t inalign .

# Create .env file (placeholder - needs manual update)
cat > /home/ec2-user/.env << 'ENVFILE'
NEO4J_URI=neo4j+s://your-instance.databases.neo4j.io
NEO4J_USERNAME=neo4j
NEO4J_PASSWORD=your-password
NEO4J_DATABASE=neo4j
PORT=8080
ENVFILE

# Run container
docker run -d \
  --name inalign \
  --restart unless-stopped \
  -p 8080:8080 \
  --env-file /home/ec2-user/.env \
  inalign

echo "=== InALign Setup Complete ==="
echo "Dashboard: http://$(curl -s http://169.254.169.254/latest/meta-data/public-ipv4):8080"
