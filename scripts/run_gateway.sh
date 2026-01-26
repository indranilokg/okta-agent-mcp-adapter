#!/bin/bash

# Okta MCP Gateway startup script

set -e

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Check Python installation
if ! command -v python3 &> /dev/null; then
    echo "Python 3 is not installed"
    exit 1
fi

echo -e "${BLUE}=====================================================================${NC}"
echo -e "${BLUE}Okta MCP Gateway${NC}"
echo -e "${BLUE}=====================================================================${NC}"

# Create virtual environment if it doesn't exist
if [ ! -d "venv" ]; then
    echo -e "${GREEN}Creating virtual environment...${NC}"
    python3 -m venv venv
fi

# Activate virtual environment
source venv/bin/activate

# Install dependencies
echo -e "${GREEN}Installing dependencies...${NC}"
pip install -q -r requirements.txt

# Copy env file if it doesn't exist
if [ ! -f ".env" ]; then
    echo -e "${GREEN}Creating .env file from template...${NC}"
    cp env.template .env
    echo -e "${BLUE}Please configure .env with your Okta credentials${NC}"
fi

# Load environment
export $(cat .env | grep -v '#' | xargs)

# Run gateway
echo -e "${GREEN}Starting gateway...${NC}"
echo -e "${BLUE}Listening on http://localhost:${GATEWAY_PORT:-8000}${NC}"
echo -e "${BLUE}Press Ctrl+C to stop${NC}"
echo ""

# Determine transport
TRANSPORT=${1:-http}

python3 -m okta_agent_proxy.main $TRANSPORT

