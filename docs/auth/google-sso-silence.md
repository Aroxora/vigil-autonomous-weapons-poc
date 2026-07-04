# Google SSO Silence — June 14, 2026

## What Happened

Google Sign-In was configured correctly in the Firebase Console for project `erosolar-1b0db`:

- **Google provider**: Enabled ✅
- **Authorized domains**:
  - `localhost` (default)
  - `erosolar-1b0db.firebaseapp.com` (default)
  - `erosolar-1b0db.web.app` (default)
  - `trenchwork.org` (custom)

All four domains were present. The Firebase configuration on the Angular frontend used the correct API key (`AIzaSyDmD4RbVRClZaM2yF2Q9Qkt-18ST7Y29X4`) and auth domain (`erosolar-1b0db.firebaseapp.com`).

Yet Google SSO failed with a silent `auth/internal-error`.

## Root Cause Analysis

After investigation, the most likely causes (in order of probability):

### 1. OAuth Consent Screen Not Published (Most Likely)

Firebase Authentication's Google provider uses Google Cloud Platform's OAuth 2.0 under the hood. Even when the Firebase Console shows "Enabled", the underlying GCP OAuth consent screen must be:

- Set to **External** (or Internal for Workspace)
- **Published** (not in "Testing" mode)
- Or have the signing-in user added as a **Test User**

If the consent screen is in "Testing" mode and the user is not on the test users list, Google's OAuth infrastructure will reject the sign-in with an opaque error. Firebase wraps this as `auth/internal-error`.

**Check**: https://console.cloud.google.com/apis/credentials/consent → Select project `erosolar-1b0db`

### 2. Identity Toolkit API Not Enabled

The Firebase Authentication service relies on the Google Identity Toolkit API. If this API is disabled in the GCP project, all Firebase Auth operations fail.

**Check**: https://console.cloud.google.com/apis/library/identitytoolkit.googleapis.com → Should show "API Enabled"

### 3. API Key Restrictions

Browser API keys in Firebase can be restricted by:
- HTTP referrer (website URLs)
- Application restrictions

If `trenchwork.org` or `erosolar-1b0db.web.app` are not in the HTTP referrer allowlist, Google will reject API calls from those domains.

**Check**: https://console.cloud.google.com/apis/credentials → API key `AIzaSyDmD4RbVRClZaM2yF2Q9Qkt-18ST7Y29X4` → Application restrictions

### 4. Browser Third-Party Cookie Restrictions

Chrome and other browsers have tightened third-party cookie policies. `signInWithPopup` opens a popup to `accounts.google.com`, which requires third-party cookies. If blocked, the popup fails silently.

**Mitigation**: Use `signInWithRedirect` (full page redirect, no popup dependency) — this was the fallback in the original code.

### 5. OAuth Client ID Mismatch

Firebase creates an OAuth 2.0 client ID automatically when Google Sign-In is enabled. If this client ID is deleted, regenerated, or if there's a mismatch between Firebase's client ID and the one in GCP, Google will reject with an opaque error.

**Check**: Firebase Console → Authentication → Sign-in method → Google → Web SDK configuration. The client ID must match the one in GCP Console → APIs & Services → Credentials.

## Timeline

| Time (UTC) | Event |
|---|---|
| June 13 ~22:00 | Google SSO configured and tested — `auth/internal-error` observed |
| June 14 01:00 | Authorized domains verified — all 4 present |
| June 14 01:15 | Google provider confirmed Enabled in Firebase Console |
| June 14 01:30 | Decision: switch to Email/Password only to unblock access |
| June 14 01:35 | Google provider disabled; Email/Password enabled via Identity Toolkit REST API |
| June 14 01:40 | User `bo@trenchwork.org` created, email verified, admin claims set |
| June 14 01:45 | All Google SSO code removed from `auth.service.ts` |
| June 14 01:50 | Site deployed with Email/Password sign-in gate |

## Why Google Does This

Google does not "nuke" SSO. The `auth/internal-error` is a catch-all for configuration mismatches between Firebase Console and Google Cloud Console. The two consoles operate on the same GCP project but have different visibility:

- **Firebase Console** shows provider status (Enabled/Disabled)
- **Google Cloud Console** controls the OAuth consent screen, API enablement, and credential restrictions

When these get out of sync — typically because the OAuth consent screen was never published after Firebase project creation — Google's OAuth infrastructure rejects sign-ins silently. Firebase catches the error and surfaces it as `auth/internal-error`.

This is a known pain point with Firebase Authentication. The solution is to either:

1. **Publish the OAuth consent screen** (requires GCP Console access)
2. **Use Email/Password authentication** (no OAuth dependency, works immediately)

## Resolution

We chose option 2. Email/Password authentication has several advantages:

- **No OAuth dependency** — works immediately after enabling
- **No consent screen required** — no GCP Console configuration needed
- **Works in all browsers** — no popup/cookie issues
- **Simpler security model** — one account type, consistent behavior
- **ECCN-compatible** — no Google account linking to ECCN-restricted content

The trade-off: users must create and verify an account manually. For a security tool with ECCN access control, this is actually an advantage — it ensures explicit intent before granting access to restricted content.

## Current State

- Email/Password: **Enabled and working**
- Google SSO: **Disabled, code removed**
- Admin user: `bo@trenchwork.org` (email verified, admin claims set)
- Sign-in page: https://trenchwork.org/security

## References

- [Firebase Auth: internal-error troubleshooting](https://firebase.google.com/docs/auth/admin/errors)
- [Google OAuth consent screen configuration](https://support.google.com/cloud/answer/10311615)
- [Firebase vs GCP Console divergence](https://firebase.google.com/docs/projects/learn-more#console-comparison)
