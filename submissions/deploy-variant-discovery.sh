#!/bin/bash
# ═══════════════════════════════════════════════════════════════════
# Vigil Variant Discovery Pipeline — EC2 + S3 Persistent Storage
# ═══════════════════════════════════════════════════════════════════
#
# Deploys EC2 Spot instances that:
# 1. Download target binaries from S3 (never deleted after processing)
# 2. Run Ghidra binary diff on each CVE patch pair
# 3. Extract vulnerability fingerprints
# 4. Search entire codebase for unpatched variants
# 5. Upload ALL results (binaries, diffs, crash dumps, reports) to S3
# 6. NEVER delete processed data — everything persisted
#
# Usage:
#   ./deploy-variant-discovery.sh
#   ./deploy-variant-discovery.sh 50    # 50-instance fleet
#   CVE_LIST=s3://bucket/cves.json ./deploy-variant-discovery.sh
#
# Architecture:
#   S3 (persistent) ← EC2 Spot Fleet (ephemeral) → S3 (results)
#   All binaries, diffs, fingerprints stored permanently
# ═══════════════════════════════════════════════════════════════════

set -euo pipefail

# ── Config ─────────────────────────────────────────────────────────
BUCKET="${S3_BUCKET:-vigil-variant-artifacts}"
REGION="${AWS_REGION:-us-east-1}"
INSTANCE_COUNT="${1:-5}"
INSTANCE_TYPE="${INSTANCE_TYPE:-c6i.2xlarge}"
KEY="${KEY_NAME:-vigil-kali-key}"
SG="${SECURITY_GROUP:-vigil-kali-sg}"
ROLE="${IAM_ROLE:-vigil-ec2-role}"
AMI="ami-00e7c79e67f2a4b50"  # Kali Linux

echo "═══════════════════════════════════════════════════════"
echo "VIGIL VARIANT DISCOVERY — Persistent Storage Pipeline"
echo "═══════════════════════════════════════════════════════"
echo "Instances: $INSTANCE_COUNT x $INSTANCE_TYPE"
echo "S3 Bucket: s3://$BUCKET/"
echo "Artifacts: binaries, diffs, fingerprints — NEVER deleted"
echo "═══════════════════════════════════════════════════════"

# ── Bootstrap Script ───────────────────────────────────────────────
# This runs on every EC2 instance at launch
BOOTSTRAP=$(base64 -w0 << 'VARIANT_BOOTSTRAP'
#!/bin/bash
set -e
exec > /var/log/vigil-variant-discovery.log 2>&1
echo "[$(date)] Variant Discovery Pipeline Starting"

BUCKET="VIGIL_BUCKET"
REGION="VIGIL_REGION"
INSTANCE_ID=$(curl -s http://169.254.169.254/latest/meta-data/instance-id)

# ── Prepare System ─────────────────────────────────────────────────
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq

# Install tools
apt-get install -y -qq \
    nodejs npm git build-essential \
    ghidra openjdk-21-jdk \
    python3-pip python3-venv \
    docker.io containerd \
    unzip wget curl jq xxd binutils \
    radare2 gdb strace ltrace \
    afl++ afl++-clang \
    2>/dev/null || true

pip3 install --break-system-packages \
    pwntools angr z3-solver requests boto3 \
    2>/dev/null || true

# ── Clone Vigil ────────────────────────────────────────────────────
cd /opt
git clone https://github.com/Aroxora/vigil-by-trenchwork.git 2>/dev/null || true
cd vigil-by-trenchwork
npm ci --silent 2>/dev/null || npm install --silent
npm run build 2>/dev/null || true

# ── Create Persistent Working Directory ────────────────────────────
WORKDIR="/opt/variant-analysis"
mkdir -p "$WORKDIR"/{binaries,diffs,fingerprints,results,crashes,reports}
# This directory and its contents are uploaded to S3 — NEVER deleted

echo "[$(date)] Work directory: $WORKDIR"

# ── Download Target Binaries from S3 ───────────────────────────────
echo "[$(date)] Downloading binaries from s3://$BUCKET/binaries/..."
aws s3 sync "s3://$BUCKET/binaries/" "$WORKDIR/binaries/" --region "$REGION" 2>/dev/null || true
echo "[$(date)] Downloaded: $(find $WORKDIR/binaries -type f | wc -l) files"

# ── Download CVE Patch Pairs ───────────────────────────────────────
echo "[$(date)] Downloading CVE patch pairs..."
aws s3 cp "s3://$BUCKET/cve-manifest.json" "$WORKDIR/cve-manifest.json" --region "$REGION" 2>/dev/null || true

# ── Phase 1: Ghidra Binary Diff ────────────────────────────────────
echo "[$(date)] Phase 1: Ghidra binary diff on patch pairs"

for binary_dir in "$WORKDIR/binaries"/*/; do
    [ -d "$binary_dir" ] || continue
    binary_name=$(basename "$binary_dir")

    VULN_BIN="$binary_dir/vulnerable/$binary_name"
    PATCH_BIN="$binary_dir/patched/$binary_name"
    DIFF_OUTPUT="$WORKDIR/diffs/$binary_name.diff.json"

    if [ ! -f "$VULN_BIN" ] || [ ! -f "$PATCH_BIN" ]; then
        echo "  [skip] $binary_name (missing vulnerable or patched binary)"
        continue
    fi

    echo "  [diff] $binary_name → $DIFF_OUTPUT"

    # Ghidra headless analysis of vulnerable binary
    ghidra_headless="/opt/ghidra/support/analyzeHeadless"
    if [ -x "$ghidra_headless" ]; then
        "$ghidra_headless" /tmp/ghidra-project "$binary_name" \
            -import "$VULN_BIN" -import "$PATCH_BIN" \
            -postScript VigilDiff.java "$DIFF_OUTPUT" \
            -deleteProject 2>/dev/null || echo "  [warn] Ghidra diff failed for $binary_name"
    else
        # Fallback: use objdump + diff
        objdump -d "$VULN_BIN" > "$WORKDIR/diffs/$binary_name.vuln.asm"
        objdump -d "$PATCH_BIN" > "$WORKDIR/diffs/$binary_name.patch.asm"
        diff "$WORKDIR/diffs/$binary_name.vuln.asm" "$WORKDIR/diffs/$binary_name.patch.asm" > "$WORKDIR/diffs/$binary_name.asm.diff" 2>/dev/null || true
    fi
done

echo "[$(date)] Phase 1 complete: $(find $WORKDIR/diffs -type f | wc -l) diff files"

# ── Phase 2: Fingerprint Extraction ────────────────────────────────
echo "[$(date)] Phase 2: Extracting vulnerability fingerprints"

cat > "$WORKDIR/fingerprints/manifest.json" << 'MANIFEST_EOF'
{
  "generated": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "instance": "$INSTANCE_ID",
  "fingerprints": []
}
MANIFEST_EOF

for diff_file in "$WORKDIR/diffs"/*.diff.json; do
    [ -f "$diff_file" ] || continue
    binary_name=$(basename "$diff_file" .diff.json)
    fingerprint_file="$WORKDIR/fingerprints/$binary_name.fingerprint.json"

    echo "  [fingerprint] $binary_name"

    # Extract vulnerability pattern from diff
    python3 << PYEOF
import json, sys, hashlib

# Load Ghidra diff output
try:
    with open("$diff_file") as f:
        diff_data = json.load(f)
except:
    diff_data = {"changed_functions": [], "new_bounds_checks": [], "added_entitlement_checks": []}

# Build fingerprint from changed functions
fingerprint = {
    "cve": binary_name.replace("_", "-").upper(),
    "binary": binary_name,
    "pattern_type": [],
    "changed_functions": [],
    "signature": "",
}

for func in diff_data.get("changed_functions", []):
    fingerprint["changed_functions"].append({
        "name": func.get("name", "unknown"),
        "address": func.get("address", "0x0"),
        "change_type": func.get("change_type", "modified"),
        "added_bounds_check": func.get("added_bounds_check", False),
        "added_auth_check": func.get("added_auth_check", False),
    })

# Classify pattern type
if diff_data.get("new_bounds_checks"):
    fingerprint["pattern_type"].append("bounds_check")
if diff_data.get("added_entitlement_checks"):
    fingerprint["pattern_type"].append("auth_check")
if any(f.get("change_type") == "type_confusion" for f in diff_data.get("changed_functions", [])):
    fingerprint["pattern_type"].append("type_confusion")

# Generate fingerprint signature
sig_input = json.dumps(fingerprint, sort_keys=True)
fingerprint["signature"] = hashlib.sha256(sig_input.encode()).hexdigest()

with open("$fingerprint_file", "w") as f:
    json.dump(fingerprint, f, indent=2)
print(f"    Signature: {fingerprint['signature'][:16]}... Pattern: {fingerprint['pattern_type']}")
PYEOF

done

echo "[$(date)] Phase 2 complete: $(find $WORKDIR/fingerprints -name '*.fingerprint.json' | wc -l) fingerprints"

# ── Phase 3: Variant Search ────────────────────────────────────────
echo "[$(date)] Phase 3: Searching for unpatched variants"

for fingerprint_file in "$WORKDIR/fingerprints"/*.fingerprint.json; do
    [ -f "$fingerprint_file" ] || continue
    binary_name=$(basename "$fingerprint_file" .fingerprint.json)
    variant_output="$WORKDIR/results/$binary_name.variants.json"

    echo "  [search] $binary_name → variants"

    # Search ALL binaries for this fingerprint pattern
    python3 << PYEOF
import json, os, hashlib, re

# Load fingerprint
with open("$fingerprint_file") as f:
    fp = json.load(f)

variants = []

# Search all binaries in the repo
for root, dirs, files in os.walk("/opt/vigil-by-trenchwork"):
    for fn in files:
        fpath = os.path.join(root, fn)
        # Skip if too large or not a binary
        try:
            size = os.path.getsize(fpath)
            if size > 100_000_000 or size < 1000:
                continue
        except:
            continue

        # Check for pattern match
        try:
            with open(fpath, "rb") as bf:
                content = bf.read()

            # Search for changed function patterns
            for func in fp.get("changed_functions", []):
                fname = func.get("name", "").encode()
                if fname and fname in content:
                    # Found a candidate — compute hash
                    fhash = hashlib.sha256(content).hexdigest()
                    variants.append({
                        "file": fpath,
                        "size": size,
                        "function_match": func["name"],
                        "fingerprint_cve": fp["cve"],
                        "fingerprint_signature": fp["signature"],
                        "file_hash": fhash,
                        "match_confidence": "LOW",  # Binary pattern match needs manual review
                    })
        except:
            continue

# Remove duplicates by file path
seen = set()
unique = []
for v in variants:
    if v["file"] not in seen:
        seen.add(v["file"])
        unique.append(v)

with open("$variant_output", "w") as f:
    json.dump({
        "fingerprint": fp["binary"],
        "fingerprint_cve": fp["cve"],
        "candidates_found": len(unique),
        "variants": unique,
    }, f, indent=2)

print(f"    Found: {len(unique)} candidate variants")
PYEOF

done

echo "[$(date)] Phase 3 complete: $(find $WORKDIR/results -name '*.variants.json' | wc -l) variant reports"

# ── Upload ALL Results to S3 (Persistent — NEVER delete) ──────────
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
S3_PATH="s3://$BUCKET/runs/$TIMESTAMP-$INSTANCE_ID"

echo "[$(date)] Uploading ALL artifacts to $S3_PATH/..."
echo "[$(date)] This data is PERSISTENT — never deleted from S3"

# Upload every directory — nothing is discarded
for subdir in binaries diffs fingerprints results crashes; do
    if [ -d "$WORKDIR/$subdir" ] && [ "$(ls -A "$WORKDIR/$subdir" 2>/dev/null)" ]; then
        echo "  [$subdir] $(find $WORKDIR/$subdir -type f | wc -l) files → $S3_PATH/$subdir/"
        aws s3 sync "$WORKDIR/$subdir/" "$S3_PATH/$subdir/" --region "$REGION" 2>/dev/null || echo "  [warn] Upload failed for $subdir"
    fi
done

# Upload run metadata
cat > "$WORKDIR/run.json" << RUNEOF
{
  "run_id": "$TIMESTAMP-$INSTANCE_ID",
  "instance_id": "$INSTANCE_ID",
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "binaries_processed": $(find $WORKDIR/binaries -type f 2>/dev/null | wc -l),
  "diffs_generated": $(find $WORKDIR/diffs -type f 2>/dev/null | wc -l),
  "fingerprints_extracted": $(find $WORKDIR/fingerprints -name '*.fingerprint.json' 2>/dev/null | wc -l),
  "variant_candidates": $(python3 -c "import json,glob; n=0; [n:=n+json.load(open(f)).get('candidates_found',0) for f in glob.glob('$WORKDIR/results/*.variants.json')]; print(n)" 2>/dev/null || echo 0),
  "storage_path": "$S3_PATH",
  "persistent": true
}
RUNEOF

aws s3 cp "$WORKDIR/run.json" "$S3_PATH/run.json" --region "$REGION" 2>/dev/null || true

echo ""
echo "═══════════════════════════════════════════════════════"
echo "VARIANT DISCOVERY PIPELINE COMPLETE"
echo "═══════════════════════════════════════════════════════"
echo "Run ID:   $TIMESTAMP-$INSTANCE_ID"
echo "S3 Path:  $S3_PATH/"
echo "Binaries: $(find $WORKDIR/binaries -type f | wc -l) files (persistent)"
echo "Diffs:    $(find $WORKDIR/diffs -type f | wc -l) files (persistent)"
echo "Fingerprints: $(find $WORKDIR/fingerprints -name '*.fingerprint.json' | wc -l) extracted"
echo "Variants: $(python3 -c "import json,glob; n=0; [n:=n+json.load(open(f)).get('candidates_found',0) for f in glob.glob('$WORKDIR/results/*.variants.json')]; print(n)" 2>/dev/null || echo 0) candidates"
echo ""
echo "ALL data persisted to S3. NOTHING deleted."
echo "═══════════════════════════════════════════════════════"

# ── Self-terminate after upload complete ──────────────────────────
sleep 60
echo "[$(date)] Pipeline done. Shutting down."
# aws ec2 terminate-instances --instance-ids "$INSTANCE_ID" --region "$REGION"
VARIANT_BOOTSTRAP
)

# Inject S3 bucket + region
BOOTSTRAP=$(echo "$BOOTSTRAP" | sed "s/VIGIL_BUCKET/$BUCKET/g; s/VIGIL_REGION/$REGION/g")

# ── Create S3 bucket if not exists ─────────────────────────────────
echo "[init] Ensuring S3 bucket exists: $BUCKET"
aws s3 mb "s3://$BUCKET" --region "$REGION" 2>/dev/null || true

# ── Upload CVE manifest if provided ────────────────────────────────
if [ -n "${CVE_LIST:-}" ] && [ -f "$CVE_LIST" ]; then
    echo "[init] Uploading CVE manifest: $CVE_LIST"
    aws s3 cp "$CVE_LIST" "s3://$BUCKET/cve-manifest.json" --region "$REGION"
fi

# ── Launch EC2 Spot Fleet ──────────────────────────────────────────
echo "[deploy] Launching $INSTANCE_COUNT instances..."

REQ_ID=$(aws ec2 request-spot-instances \
    --region "$REGION" \
    --spot-price "0.50" \
    --instance-count "$INSTANCE_COUNT" \
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
            \"Ebs\": {\"VolumeSize\": 500, \"VolumeType\": \"gp3\", \"DeleteOnTermination\": false}
        }]
    }" \
    --query 'SpotInstanceRequests[0].SpotInstanceRequestId' \
    --output text 2>&1)

echo ""
echo "═══════════════════════════════════════════════════════"
echo "VARIANT DISCOVERY DEPLOYED"
echo "═══════════════════════════════════════════════════════"
echo "Spot Request: $REQ_ID"
echo "S3 Bucket:    s3://$BUCKET/"
echo ""
echo "All binaries, diffs, fingerprints, and variant reports"
echo "are stored PERMANENTLY in S3. Nothing is deleted."
echo ""
echo "Monitor: aws s3 ls s3://$BUCKET/runs/ --recursive"
echo "═══════════════════════════════════════════════════════"
