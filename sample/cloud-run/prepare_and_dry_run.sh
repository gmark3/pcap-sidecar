#!/bin/bash

# Create the service YAML file with variable substitutions.
sed -e "s|PLACEHOLDER_SERVICE_NAME|$SERVICE_NAME|g" \
    -e "s|PLACEHOLDER_PCAP_GCS_BUCKET|$PCAP_GCS_BUCKET|g" \
    cloudrun.yaml > service.yaml

# Perform a dry-run.
gcloud run services replace service.yaml --project="$PROJECT_ID" --region="$REGION" --dry-run

echo ""
echo "If the dry-run looks good, run the following command to deploy:"
echo "gcloud run services replace service.yaml --project=\"$PROJECT_ID\" --region=\"$REGION\""