#!/bin/bash

# update.sh - Update skills from repo

set -e

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "🔄 Updating personal skills..."

# Pull latest changes
cd "$REPO_DIR"
git pull origin master

# Run installation
./install.sh

echo "✅ Skills updated to latest version!"
