# Unified Cloud Auto-Update Service
## No Firebase CLI · No AWS CLI · No GCloud CLI Required at Runtime

### Architecture

```
┌─────────────────────────────────────────────────────────────┐
│           Unified Auto-Update Service (cloud-auto-update)    │
├─────────────────────────────────────────────────────────────┤
│  GCloud Compute  │   AWS EC2 (Kali)  │   Azure VM (Kali)   │
│  (Container VM)  │  (Spot Instance)  │  (Spot VM)          │
│       │          │        │          │       │              │
│       └──────────┴────────┴──────────┘       │              │
│                     │                         │              │
│              ┌──────┴──────┐                   │              │
│              │ Docker Hub  │ ← push on commit  │              │
│              │ (vigil:latest)│                  │              │
│              └──────┬──────┘                   │              │
│                     │                         │              │
│  ┌──────────────────┼─────────────────────────┤              │
│  │  All instances pull & run same container:  │              │
│  │  docker pull trenchwork/vigil:latest       │              │
│  │  docker run ... /opt/auto-update.sh       │              │
│  └────────────────────────────────────────────┘              │
│                                                              │
│  Updates:                                                    │
│  • Firebase Hosting → docker run firebase deploy             │
│  • AWS Lambda       → docker run aws lambda update           │
│  • CDN / Firestore  → HTTP API calls to Lambda (no CLI)      │
│  • Health check     → /api/health polling                    │
└─────────────────────────────────────────────────────────────┘
```

### How It Works (No CLI Required at Runtime)

1. **Docker image** is built via GitHub Actions and pushed to Docker Hub
2. **Each cloud instance** pulls the latest image on boot via `docker run`
3. **Firebase deploy** happens inside the container using a service account key (not Firebase CLI login)
4. **AWS Lambda deploy** happens via `aws lambda update-function-code` inside the container
5. **CDN refresh** happens via HTTP POST to Lambda `/api/hourlyUpdate` (no AWS CLI needed)
6. **Health monitoring** via HTTP GET to `/api/health` (no tools needed)

### Key Principle: Service Account Keys, Not CLI Logins

| Operation | CLI Required? | Alternative |
|-----------|--------------|-------------|
| Firebase Hosting deploy | `firebase deploy --token` | Service account + `GOOGLE_APPLICATION_CREDENTIALS` |
| Firebase Functions deploy | `firebase deploy --only functions` | Service account inside Docker |
| AWS Lambda update | `aws lambda update-function-code` | HTTP API to Lambda itself (self-update) |
| CDN cache refresh | `aws s3 cp` | HTTP POST `/api/hourlyUpdate` |
| Firestore write | `firebase firestore:update` | HTTP API to Lambda |
| Health check | CLI tooling | HTTP GET `/api/health` |
| Secrets access | `aws secretsmanager` | Lambda has IAM role — just read env vars |
