# AgentShield Deployment Guide

## Local Development (Docker Compose)

### Prerequisites

- Docker Desktop (or Docker Engine + Docker Compose)
- Git

### Quick Start

1. Clone the repository:

```bash
git clone https://github.com/agentshield/agentshield.git
cd agentshield
```

2. Copy the environment file:

```bash
cp .env.example .env
```

3. Edit `.env` with your configuration values.

4. Start all services:

```bash
make dev
# or
docker-compose -f infra/docker/docker-compose.yml up -d
```

5. Verify services are running:

```bash
docker-compose -f infra/docker/docker-compose.yml ps
```

6. Access the services:
   - Backend API: http://localhost:8000
   - API Docs: http://localhost:8000/docs
   - Frontend: http://localhost:3000
   - Neo4j Browser: http://localhost:7474

### Useful Commands

```bash
# View logs
make logs

# Stop services
make down

# Rebuild after code changes
make build

# Run database migrations
make migrate

# Seed test data
make seed

# Run tests
make test

# Run linter
make lint

# Clean up everything (volumes included)
make clean
```

## Production Deployment (Kubernetes)

### Prerequisites

- Kubernetes cluster (1.25+)
- kubectl configured
- Helm 3 (optional, for cert-manager)
- Container registry access (e.g., GitHub Container Registry)

### Step 1: Create the Namespace

```bash
kubectl apply -f infra/k8s/namespace.yaml
```

### Step 2: Configure Secrets

Edit `infra/k8s/secrets.yaml` with your actual base64-encoded values:

```bash
# Encode a value
echo -n "your-actual-password" | base64

# Apply secrets
kubectl apply -f infra/k8s/secrets.yaml
```

**Important:** Never commit actual secrets to version control. Use a secrets manager like HashiCorp Vault, AWS Secrets Manager, or Sealed Secrets in production.

### Step 3: Deploy Data Stores

Deploy the stateful services first:

```bash
kubectl apply -f infra/k8s/postgres-statefulset.yaml
kubectl apply -f infra/k8s/neo4j-statefulset.yaml
kubectl apply -f infra/k8s/redis-deployment.yaml
```

Wait for them to be ready:

```bash
kubectl get pods -n agentshield -w
```

### Step 4: Deploy Application

```bash
kubectl apply -f infra/k8s/backend-deployment.yaml
kubectl apply -f infra/k8s/frontend-deployment.yaml
```

### Step 5: Configure Ingress

Install cert-manager for TLS (if not already installed):

```bash
helm repo add jetstack https://charts.jetstack.io
helm install cert-manager jetstack/cert-manager --namespace cert-manager --create-namespace --set installCRDs=true
```

Apply the ingress:

```bash
kubectl apply -f infra/k8s/ingress.yaml
```

### Step 6: Verify Deployment

```bash
# Check all resources
kubectl get all -n agentshield

# Check ingress
kubectl get ingress -n agentshield

# Check pod logs
kubectl logs -f deployment/backend -n agentshield

# Port-forward for local testing
kubectl port-forward svc/backend 8000:8000 -n agentshield
```

### Scaling

```bash
# Scale backend
kubectl scale deployment/backend --replicas=5 -n agentshield

# Scale frontend
kubectl scale deployment/frontend --replicas=3 -n agentshield

# Set up HPA (Horizontal Pod Autoscaler)
kubectl autoscale deployment/backend --min=3 --max=10 --cpu-percent=70 -n agentshield
```

## Environment Variables Reference

### Application

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `API_HOST` | API bind host | `0.0.0.0` | No |
| `API_PORT` | API bind port | `8000` | No |
| `API_ENV` | Environment (development/staging/production) | `development` | No |
| `SECRET_KEY` | Application secret key | - | Yes |
| `ALLOWED_ORIGINS` | CORS allowed origins (comma-separated) | `http://localhost:3000` | No |

### PostgreSQL

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `POSTGRES_HOST` | PostgreSQL host | `localhost` | Yes |
| `POSTGRES_PORT` | PostgreSQL port | `5432` | No |
| `POSTGRES_DB` | Database name | `agentshield` | Yes |
| `POSTGRES_USER` | Database user | `agentshield` | Yes |
| `POSTGRES_PASSWORD` | Database password | - | Yes |

### Neo4j

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `NEO4J_URI` | Neo4j Bolt URI | `bolt://localhost:7687` | Yes |
| `NEO4J_USER` | Neo4j username | `neo4j` | Yes |
| `NEO4J_PASSWORD` | Neo4j password | - | Yes |
| `NEO4J_DATABASE` | Neo4j database name | `agentshield` | No |

### Redis

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `REDIS_URL` | Redis connection URL | `redis://localhost:6379/0` | Yes |

### External APIs

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `OPENAI_API_KEY` | OpenAI API key (for report generation) | - | No |
| `ANTHROPIC_API_KEY` | Anthropic API key (for report generation) | - | No |

### Notifications

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `SLACK_WEBHOOK_URL` | Slack webhook for notifications | - | No |
| `TELEGRAM_BOT_TOKEN` | Telegram bot token | - | No |
| `TELEGRAM_CHAT_ID` | Telegram chat ID | - | No |
| `SENDGRID_API_KEY` | SendGrid API key for email alerts | - | No |

### Rate Limiting

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `RATE_LIMIT_PER_MINUTE` | Max API requests per minute per key | `100` | No |

## Monitoring and Observability

### Recommended Stack

- **Metrics**: Prometheus + Grafana
- **Logging**: ELK Stack or Loki
- **Tracing**: Jaeger or Zipkin

### Health Endpoints

- Backend: `GET /health`
- Neo4j: TCP port 7687
- PostgreSQL: `pg_isready`
- Redis: `redis-cli ping`

## Backup Strategy

### PostgreSQL

```bash
# Backup
kubectl exec -n agentshield postgres-0 -- pg_dump -U agentshield agentshield > backup.sql

# Restore
kubectl exec -i -n agentshield postgres-0 -- psql -U agentshield agentshield < backup.sql
```

### Neo4j

```bash
# Use neo4j-admin for backup
kubectl exec -n agentshield neo4j-0 -- neo4j-admin database dump agentshield --to-path=/backups/
```

### Redis

Redis data is ephemeral (cache). Configure AOF persistence for durability if needed.
