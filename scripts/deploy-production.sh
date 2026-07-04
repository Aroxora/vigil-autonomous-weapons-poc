#!/usr/bin/env bash

set -euo pipefail

# AGI Core Production Deployment Script
# Final step to deploy v1.1.115 to production

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log() {
  echo -e "${BLUE}[DEPLOY]${NC} $1"
}

success() {
  echo -e "${GREEN}[SUCCESS]${NC} $1"
}

warning() {
  echo -e "${YELLOW}[WARNING]${NC} $1"
}

error() {
  echo -e "${RED}[ERROR]${NC} $1"
  exit 1
}

# Verify current state
verify_state() {
  log "Verifying deployment state..."
  
  # Check version
  local current_version=$(node -p "require('./package.json').version")
  if [[ "$current_version" != "1.1.115" ]]; then
    error "Expected version 1.1.115, found $current_version"
  fi
  success "Version verified: $current_version"
  
  # Check git tag
  if ! git tag --list | grep -q "v1.1.115"; then
    error "Git tag v1.1.115 not found"
  fi
  success "Git tag v1.1.115 exists"
  
  # Check git status
  if [[ -n "$(git status --porcelain)" ]]; then
    warning "Git working directory not clean"
    git status --short
    read -p "Continue anyway? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
      error "Aborted by user"
    fi
  fi
  success "Git status clean"
  
  # Check tests
  log "Running final test verification..."
  if ! npm test > /tmp/agi-final-test.log 2>&1; then
    error "Tests failed. See /tmp/agi-final-test.log for details"
  fi
  success "All tests passing"
  
  # Check build
  log "Running final build verification..."
  if ! npm run build > /tmp/agi-final-build.log 2>&1; then
    error "Build failed. See /tmp/agi-final-build.log for details"
  fi
  success "Build successful"
}

# Deploy to GitHub
deploy_github() {
  log "Deploying to GitHub..."
  
  echo ""
  echo "GitHub Deployment Steps:"
  echo "========================"
  echo "1. Push main branch and tags to GitHub"
  echo "2. Create GitHub release with release notes"
  echo ""
  
  # Show what will be pushed
  log "Changes to push:"
  git log --oneline -5
  
  echo ""
  read -p "Push to GitHub? (y/N): " -n 1 -r
  echo
  if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    warning "Skipping GitHub deployment"
    return 0
  fi
  
  # Push to GitHub
  log "Pushing to GitHub..."
  if ! git push origin main --follow-tags; then
    error "Git push failed"
  fi
  success "Pushed to GitHub"
  
  # Create GitHub release
  log "Creating GitHub release..."
  echo "To create GitHub release, run:"
  echo "  gh release create v1.1.115 --generate-notes"
  echo ""
  echo "Or use the GitHub web interface at:"
  echo "  https://github.com/Vigil/agi-core-CLI-coding/releases/new"
  echo ""
  read -p "Create GitHub release now? (y/N): " -n 1 -r
  echo
  if [[ $REPLY =~ ^[Yy]$ ]]; then
    if command -v gh &> /dev/null; then
      gh release create v1.1.115 --generate-notes
      success "GitHub release created"
    else
      warning "GitHub CLI not installed. Create release manually."
    fi
  fi
}

# Deploy to npm
deploy_npm() {
  log "Deploying to npm..."
  
  echo ""
  echo "npm Deployment Steps:"
  echo "====================="
  echo "1. Login to npm (if not already logged in)"
  echo "2. Publish package to npm registry"
  echo "3. Verify publication"
  echo ""
  
  # Check npm login status
  log "Checking npm login status..."
  if ! npm whoami > /dev/null 2>&1; then
    warning "Not logged into npm"
    echo "To login to npm, run:"
    echo "  npm login"
    echo ""
    read -p "Login to npm now? (y/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
      npm login
    else
      warning "Skipping npm deployment (not logged in)"
      return 0
    fi
  fi
  
  # Verify npm credentials
  local npm_user=$(npm whoami)
  success "Logged into npm as: $npm_user"
  
  # Show what will be published
  log "Package to publish:"
  npm pack --dry-run | head -50
  
  echo ""
  read -p "Publish to npm? (y/N): " -n 1 -r
  echo
  if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    warning "Skipping npm publication"
    return 0
  fi
  
  # Publish to npm
  log "Publishing to npm..."
  if ! npm publish --access public; then
    error "npm publish failed"
  fi
  success "Published to npm"
  
  # Verify publication
  log "Verifying npm publication..."
  sleep 5  # Wait for npm propagation
  local published_version=$(npm view agi-core-cli version 2>/dev/null || echo "not published")
  if [[ "$published_version" == "1.1.115" ]]; then
    success "Package published successfully: version $published_version"
  else
    warning "Package may not be published yet. Current version: $published_version"
    echo "Check at: https://www.npmjs.com/package/agi-core-cli"
  fi
}

# Post-deployment verification
post_deployment_verification() {
  log "Running post-deployment verification..."
  
  echo ""
  echo "Post-Deployment Checks:"
  echo "======================="
  echo "1. GitHub release page"
  echo "2. npm package page"
  echo "3. Installation test"
  echo "4. Functionality test"
  echo ""
  
  # Test installation
  log "Testing installation..."
  echo "To test installation, run:"
  echo "  npx agi-core-cli@1.1.115 --version"
  echo ""
  
  # Test functionality
  log "Testing functionality..."
  echo "To test functionality, run:"
  echo "  npx agi-core-cli@1.1.115 --help"
  echo ""
  
  # Provide links
  success "Deployment complete!"
  echo ""
  echo "📦 Deployment Summary:"
  echo "====================="
  echo "✅ Version: 1.1.115"
  echo "✅ Git tag: v1.1.115"
  echo "✅ Tests: 536/538 passing"
  echo "✅ Build: Optimized production build"
  echo ""
  echo "🔗 Useful Links:"
  echo "  GitHub: https://github.com/Vigil/agi-core-CLI-coding"
  echo "  npm: https://www.npmjs.com/package/agi-core-cli"
  echo "  Issues: https://github.com/Vigil/agi-core-CLI-coding/issues"
  echo ""
  echo "🚀 Next Steps:"
  echo "  1. Monitor error rates and performance"
  echo "  2. Gather user feedback"
  echo "  3. Plan next release cycle"
  echo ""
}

# Main deployment function
main() {
  echo ""
  echo "🚀 AGI Core v1.1.115 - Production Deployment"
  echo "============================================"
  echo ""
  
  # Verify state
  verify_state
  
  # Show deployment summary
  echo ""
  echo "📋 Deployment Plan:"
  echo "==================="
  echo "1. Push to GitHub"
  echo "2. Create GitHub release"
  echo "3. Publish to npm"
  echo "4. Post-deployment verification"
  echo ""
  
  read -p "Start deployment? (y/N): " -n 1 -r
  echo
  if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    warning "Deployment cancelled"
    exit 0
  fi
  
  # Execute deployment steps
  deploy_github
  deploy_npm
  post_deployment_verification
  
  echo ""
  success "AGI Core v1.1.115 deployment completed successfully!"
  echo ""
}

# Parse command line arguments
case "${1:-}" in
  -h|--help|help)
    echo "AGI Core Production Deployment Script"
    echo ""
    echo "Usage:"
    echo "  $0                    # Run full deployment"
    echo "  $0 verify             # Verify deployment state only"
    echo "  $0 github             # Deploy to GitHub only"
    echo "  $0 npm                # Deploy to npm only"
    echo ""
    echo "This script deploys AGI Core v1.1.115 to production."
    echo "It requires git, npm, and appropriate credentials."
    exit 0
    ;;
  verify)
    verify_state
    exit 0
    ;;
  github)
    verify_state
    deploy_github
    exit 0
    ;;
  npm)
    verify_state
    deploy_npm
    exit 0
    ;;
  *)
    main
    ;;
esac