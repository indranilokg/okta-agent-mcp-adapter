#!/bin/bash
set -e
if [ -n "$CONFIG_YAML" ]; then
    echo "$CONFIG_YAML" > config/config.yaml
fi
python -m okta_agent_proxy.main http