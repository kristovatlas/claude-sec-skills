#!/bin/bash

# install.sh - Deploy personal Claude Code skills

set -e

SKILLS_DIR="$HOME/.claude/skills"
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "🤖 Installing personal Claude Code skills..."

# Create skills directory if it doesn't exist
mkdir -p "$SKILLS_DIR"

# Copy each skill from repo to ~/.claude/skills/
for skill in "$REPO_DIR/skills"/*/ ; do
    skill_name=$(basename "$skill")
    echo "Installing: $skill_name"
    
    # Remove existing skill if present
    rm -rf "$SKILLS_DIR/$skill_name"
    
    # Copy skill to personal directory
    cp -r "$skill" "$SKILLS_DIR/$skill_name"
done

echo "✅ Installation complete!"
echo "Installed skills in: $SKILLS_DIR"
echo ""
echo "Available skills:"
ls -1 "$SKILLS_DIR"
