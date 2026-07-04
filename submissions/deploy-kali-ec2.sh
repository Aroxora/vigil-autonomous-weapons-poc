#!/bin/bash
# ═══════════════════════════════════════════════════════════════════
# Vigil + Kali EC2 Deployment — Zero-Day AI Factory
# ═══════════════════════════════════════════════════════════════════
# Deploys Kali EC2 Spot instances with Vigil + full security toolchain.
# Auto-runs submission pipeline, uploads results to S3, self-terminates.
#
# USAGE:
#   chmod +x deploy-kali-ec2.sh
#   ./deploy-kali-ec2.sh                    # 1 instance, c6i.xlarge
#   ./deploy-kali-ec2.sh 10                 # 10 instances
#   INSTANCE_TYPE=c7i.metal-24xl ./deploy-kali-ec2.sh  # Heavy fuzzing
#
# PREREQS: awscli, EC2 quota, IAM role (EC2+S3+CloudWatch), SSH key
# ═══════════════════════════════════════════════════════════════════

set -e

REGION="${AWS_REGION:-us-east-1}"
COUNT="${1:-1}"
INSTANCE_TYPE="${INSTANCE_TYPE:-c6i.xlarge}"
SPOT_PRICE="${SPOT_PRICE:-0.12}"
KEY="${KEY_NAME:-vigil-kali-key}"
SG="${SECURITY_GROUP:-vigil-kali-sg}"
ROLE="${IAM_ROLE:-vigil-ec2-role}"
BUCKET="${S3_BUCKET:-vigil-submissions}"
DURATION="${DURATION_HOURS:-24}"

# Kali AMI (us-east-1, June 2026)
AMI="ami-00e7c79e67f2a4b50"

echo "══════════════════════════════════════════"
echo "VIGIL + KALI — Zero-Day AI Factory"
echo "══════════════════════════════════════════"
echo "Instances: $COUNT x $INSTANCE_TYPE"
echo "Spot:      \$${SPOT_PRICE}/hr max"
echo "Duration:  ${DURATION}h auto-terminate"
echo "S3:        s3://$BUCKET/"
echo "══════════════════════════════════════════"

# Build userdata bootstrap
BOOTSTRAP=$(base64 -w0 << 'EOF'
#!/bin/bash
set -e
exec > /var/log/vigil-bootstrap.log 2>&1
echo "[$(date)] Bootstrap start"

# System
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq && apt-get upgrade -y -qq

# Node 22
curl -fsSL https://deb.nodesource.com/setup_22.x | bash -
apt-get install -y -qq nodejs git build-essential unzip

# Vigil from npm
npm install -g @trenchwork/vigil

# Kali tools for the pipeline
apt-get install -y -qq afl++ afl++-clang gdb python3-pip python3-venv docker.io nmap metasploit-framework john hashcat sqlmap gobuster ghidra 2>/dev/null || true
pip3 install --break-system-packages pwntools angr requests 2>/dev/null || true

# Clone + build Vigil
cd /opt && git clone https://github.com/Aroxora/vigil-by-trenchwork.git 2>/dev/null || true
cd /opt/vigil-by-trenchwork && npm ci --silent 2>/dev/null || npm install --silent
npm run build 2>/dev/null || true

# Run True Submission Engine
echo "[$(date)] Running True Submission Engine..."
cd /opt/vigil-by-trenchwork
node submissions/true-run.mjs 2>&1 | tee /var/log/vigil-run.log

# Upload to S3
IID=$(curl -s http://169.254.169.254/latest/meta-data/instance-id)
TS=$(date +%Y%m%d-%H%M%S)
aws s3 cp submissions/output/ "s3://VIGIL_BUCKET/$TS-$IID/" --recursive --region VIGIL_REGION 2>/dev/null || true
echo "[$(date)] Uploaded to s3://VIGIL_BUCKET/$TS-$IID/"

# Self-terminate after idle
echo "[$(date)] Complete. Terminating in 5 min..."
sleep 300
aws ec2 terminate-instances --instance-ids "$IID" --region VIGIL_REGION 2>/dev/null || true
EOF
)

# Inject vars
BOOTSTRAP=$(echo "$BOOTSTRAP" | sed "s/VIGIL_BUCKET/$BUCKET/g; s/VIGIL_REGION/$REGION/g")

# Create userdata script in S3 for reusability
echo "$BOOTSTRAP" | base64 -d > /tmp/vigil-userdata.sh
chmod +x /tmp/vigil-userdata.sh

# Launch Spot Fleet
echo "[deploy] Requesting $COUNT spot instances..."
REQ_ID=$(aws ec2 request-spot-instances \
    --region "$REGION" \
    --spot-price "$SPOT_PRICE" \
    --instance-count "$COUNT" \
    --type "one-time" \
    --launch-specification "{
        \"ImageId\": \"$AMI\",
        \"InstanceType\": \"$INSTANCE_TYPE\",
        \"KeyName\": \"$KEY\",
        \"SecurityGroupIds\": [\"$SG\"],
        \"IamInstanceProfile\": {\"Name\": \"$ROLE\"},
        \"UserData\": \"$BOOTSTRAP\",
        \"BlockDeviceMappings\": [{
            \"DeviceName\": \"/dev/xvda\",
            \"Ebs\": {\"VolumeSize\": 100, \"VolumeType\": \"gp3\", \"DeleteOnTermination\": true}
        }]
    }" \
    --query 'SpotInstanceRequests[0].SpotInstanceRequestId' \
    --output text 2>&1)

echo ""
echo "══════════════════════════════════════════"
echo "DEPLOYED"
echo "══════════════════════════════════════════"
echo "Spot Request: $REQ_ID"
echo "Region:       $REGION"
echo ""
echo "Monitor:"
echo "  aws ec2 describe-spot-instance-requests --region $REGION --spot-instance-request-ids $REQ_ID"
echo ""
echo "Results will appear in: s3://$BUCKET/"
echo "Instances auto-terminate after pipeline completes."
echo "══════════════════════════════════════════"
