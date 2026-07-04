#!/bin/bash
# ================================================================
# Azure Auto-Update Service — Kali Linux Spot VM
# Deploys on Azure Container Instances or VM. No az CLI at runtime.
# ================================================================
set -euo pipefail

RG="${AZURE_RG:-vigil-cne-rg}"
LOCATION="${AZURE_LOCATION:-eastus}"
VM_NAME="vigil-auto-update"
VM_SIZE="${VM_SIZE:-Standard_D2s_v3}"
CONTAINER_IMAGE="trenchwork/vigil:latest"
FIREBASE_PROJECT="erosolar-1b0db"

echo "=== Azure VM — Vigil Auto-Update ==="
echo "Resource Group: $RG | Location: $LOCATION | VM: $VM_NAME"
echo ""

STARTUP_SCRIPT=$(cat <<'SCRIPT'
#!/bin/bash
set -euo pipefail
exec > /var/log/vigil-startup.log 2>&1
echo "=== Vigil Azure Auto-Update $(date -u) ==="

# Install Docker
if ! command -v docker &>/dev/null; then
  apt-get update -qq && apt-get install -y -qq docker.io curl jq
  systemctl start docker
fi

echo "[1/4] Pulling latest image..."
docker pull trenchwork/vigil:latest || echo "Pull attempted"

echo "[2/4] Firebase deploy (service account, no CLI login)..."
docker run --rm \
  -v /etc/vigil/firebase-admin.json:/firebase-admin.json:ro \
  -e GOOGLE_APPLICATION_CREDENTIALS=/firebase-admin.json \
  trenchwork/vigil:latest bash -c '
    cd /opt/vigil/site && \
    npx firebase-tools deploy --only hosting --project erosolar-1b0db --non-interactive
  ' || echo "Firebase deploy attempted"

echo "[3/4] CDN refresh via HTTP (no CLI)..."
curl -sf -X POST "https://cfqeqx4lt9.execute-api.us-east-1.amazonaws.com/api/hourlyUpdate" || true

echo "[4/4] Scheduling hourly cron..."
echo "0 * * * * root bash /opt/vigil/cloud-auto-update/azure/boot.sh >> /var/log/vigil-cron.log 2>&1" > /etc/cron.d/vigil-hourly

echo "=== Boot Complete $(date -u) ==="
SCRIPT
)

deploy_vm() {
  echo "Creating Azure VM..."
  az vm create \
    --resource-group "$RG" \
    --name "$VM_NAME" \
    --image "kali-linux:kali-linux:kali-linux:latest" \
    --size "$VM_SIZE" \
    --admin-username vigil \
    --generate-ssh-keys \
    --public-ip-sku Standard \
    --custom-data <(echo "$STARTUP_SCRIPT" | base64 -w0) \
    --priority Spot \
    --max-price -1 \
    --eviction-policy Delete \
    --tags vigil-auto-update cne-only kali-linux \
    2>/dev/null || echo "VM may already exist"

  az vm open-port --resource-group "$RG" --name "$VM_NAME" --port 80,443,3000 2>/dev/null || true

  IP=$(az vm show -d -g "$RG" -n "$VM_NAME" --query publicIps -o tsv)
  echo "VM IP: $IP"
}

deploy_aci() {
  echo "Creating Azure Container Instance (serverless, no VM management)..."
  az container create \
    --resource-group "$RG" \
    --name "${VM_NAME}-aci" \
    --image "$CONTAINER_IMAGE" \
    --cpu 2 --memory 4 \
    --restart-policy Always \
    --environment-variables \
      FIREBASE_PROJECT="$FIREBASE_PROJECT" \
      VIGIL_GHIDRA_HEADLESS=0 \
      VIGIL_GHIDRA_MCP_ONLY=1 \
    --location "$LOCATION" \
    2>/dev/null || echo "ACI may already exist"

  az container show --resource-group "$RG" --name "${VM_NAME}-aci" \
    --query "{IP:ipAddress.ip,State:instanceView.state}" -o table
}

case "${1:-vm}" in
  vm)   deploy_vm ;;
  aci)  deploy_aci ;;
  destroy)
    az vm delete --resource-group "$RG" --name "$VM_NAME" --yes
    az container delete --resource-group "$RG" --name "${VM_NAME}-aci" --yes
    ;;
  *) echo "Usage: $0 [vm|aci|destroy]" ;;
esac
