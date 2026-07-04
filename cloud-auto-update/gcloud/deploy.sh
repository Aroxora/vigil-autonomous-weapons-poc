#!/bin/bash
# ================================================================
# GCloud Auto-Update Service — Kali Linux Container VM
# Deploys on GCloud Compute Engine. No gcloud CLI needed at runtime.
# The instance auto-pulls latest Docker image + runs the update loop.
# ================================================================
set -euo pipefail

PROJECT_ID="${GCLOUD_PROJECT:-vigil-cne}"
ZONE="${GCLOUD_ZONE:-us-central1-a}"
INSTANCE_NAME="vigil-auto-update"
MACHINE_TYPE="${MACHINE_TYPE:-e2-standard-2}"
DISK_SIZE="${DISK_SIZE:-50GB}"
CONTAINER_IMAGE="trenchwork/vigil:latest"
FIREBASE_PROJECT="erosolar-1b0db"

echo "=== GCloud Compute — Vigil Auto-Update ==="
echo "Project: $PROJECT_ID | Zone: $ZONE | Instance: $INSTANCE_NAME"
echo "OS: Kali Linux (container-optimized) | Machine: $MACHINE_TYPE"
echo ""

# --- Startup script: runs once on boot, no gcloud CLI needed after ---
STARTUP_SCRIPT=$(cat <<'EOF'
#!/bin/bash
set -euo pipefail
exec > /var/log/vigil-startup.log 2>&1
echo "=== Vigil Auto-Update Boot $(date -u) ==="

# Install Docker (if not present)
if ! command -v docker &>/dev/null; then
  apt-get update -qq && apt-get install -y -qq docker.io curl jq
  systemctl start docker
fi

# Pull latest image from Docker Hub (or GitHub Container Registry)
echo "[1/5] Pulling latest image..."
docker pull trenchwork/vigil:latest || docker pull ghcr.io/aroxora/vigil:latest

# Run firebase deploy inside container (uses service account key, not CLI login)
echo "[2/5] Firebase deploy..."
docker run --rm \
  -v /etc/vigil/firebase-admin.json:/firebase-admin.json:ro \
  -e GOOGLE_APPLICATION_CREDENTIALS=/firebase-admin.json \
  -e FIREBASE_PROJECT=erosolar-1b0db \
  trenchwork/vigil:latest bash -c '
    cd /opt/vigil/site && \
    npx firebase-tools deploy --only hosting --project erosolar-1b0db --non-interactive --token "" 2>/dev/null || \
    npx firebase-tools deploy --only hosting --project erosolar-1b0db --non-interactive
  '

# CDN + Firestore refresh via Lambda (HTTP — no AWS CLI needed)
echo "[3/5] CDN cache refresh..."
curl -sf -X POST "https://cfqeqx4lt9.execute-api.us-east-1.amazonaws.com/api/hourlyUpdate" \
  -H "Content-Type: application/json" || echo "CDN refresh attempted"

# Health check
echo "[4/5] Health verification..."
HEALTH=$(curl -sf "https://cfqeqx4lt9.execute-api.us-east-1.amazonaws.com/api/health")
echo "Health: $HEALTH"

# Self-schedule next run via cron inside the container
echo "[5/5] Scheduling hourly cron..."
echo "0 * * * * root /opt/vigil/cloud-auto-update/gcloud/boot.sh >> /var/log/vigil-cron.log 2>&1" > /etc/cron.d/vigil-hourly

echo "=== Boot Complete $(date -u) ==="
EOF
)

# --- Deploy GCloud Instance ---
deploy() {
  echo "Creating GCloud Compute instance..."

  gcloud compute instances create-with-container "$INSTANCE_NAME" \
    --project="$PROJECT_ID" \
    --zone="$ZONE" \
    --machine-type="$MACHINE_TYPE" \
    --boot-disk-size="$DISK_SIZE" \
    --boot-disk-type=pd-ssd \
    --container-image="$CONTAINER_IMAGE" \
    --container-restart-policy=always \
    --container-env="FIREBASE_PROJECT=$FIREBASE_PROJECT" \
    --container-env="VIGIL_SESSION_TOKEN=gcloud-$(date +%s)" \
    --container-env="VIGIL_GHIDRA_HEADLESS=0" \
    --container-env="VIGIL_GHIDRA_MCP_ONLY=1" \
    --metadata=startup-script="$STARTUP_SCRIPT" \
    --tags=http-server,https-server \
    --scopes=cloud-platform \
    --labels=os=kali-linux,service=vigil-auto-update,purpose=cne-only \
    2>/dev/null || echo "Instance already exists — updating..."

  # Allow HTTP/HTTPS
  gcloud compute firewall-rules create allow-vigil-web \
    --project="$PROJECT_ID" \
    --allow=tcp:80,tcp:443,tcp:3000,tcp:8080 \
    --target-tags=http-server,https-server \
    2>/dev/null || echo "Firewall rule exists"

  echo ""
  echo "Instance: $INSTANCE_NAME"
  echo "Zone:     $ZONE"
  echo "Image:    $CONTAINER_IMAGE"
  echo "OS:       Kali Linux (container-optimized)"
  echo "Schedule: Hourly auto-update via cron + startup on boot"
  echo ""
  echo "SSH:  gcloud compute ssh $INSTANCE_NAME --zone=$ZONE --project=$PROJECT_ID"
  echo "Logs: gcloud compute ssh $INSTANCE_NAME --zone=$ZONE --project=$PROJECT_ID -- 'docker logs \$(docker ps -q)'"
}

# --- Destroy ---
destroy() {
  echo "Destroying $INSTANCE_NAME..."
  gcloud compute instances delete "$INSTANCE_NAME" \
    --project="$PROJECT_ID" --zone="$ZONE" --quiet
}

case "${1:-deploy}" in
  deploy)  deploy ;;
  destroy) destroy ;;
  status)
    gcloud compute instances describe "$INSTANCE_NAME" \
      --project="$PROJECT_ID" --zone="$ZONE" \
      --format="table(name,status,machineType,networkInterfaces[0].accessConfigs[0].natIP)"
    ;;
  *) echo "Usage: $0 [deploy|destroy|status]" ;;
esac
