# For Cloud (AWS/Azure/GCP):


#!/bin/bash
# cloud-init script for auto-deployment

# Install on any cloud VM
curl -sSL https://install.quantumkernel.com | bash

# Auto-configure for cloud environment
/usr/local/bin/quantum_kernel_daemon \
  --cloud aws \
  --auto-configure \
  --integration cloudflare,aws-waf
