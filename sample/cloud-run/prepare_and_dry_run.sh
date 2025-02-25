#!/bin/bash

# Print all environment variables used in the script
echo "Environment Variables:"
printf "%-20s: %s\n" "PROJECT_ID" "$PROJECT_ID"
printf "%-20s: %s\n" "SERVICE_NAME" "$SERVICE_NAME"
printf "%-20s: %s\n" "PCAP_GCS_BUCKET" "$PCAP_GCS_BUCKET"
printf "%-20s: %s\n" "REGION" "$REGION"
printf "%-20s: %s\n" "SERVICE_ACCOUNT" "$SERVICE_ACCOUNT" # Added line

# Create the service YAML file with variable substitutions.
sed -e "s|PLACEHOLDER_SERVICE_NAME|$SERVICE_NAME|g" \
    -e "s|PLACEHOLDER_PCAP_GCS_BUCKET|$PCAP_GCS_BUCKET|g" \
    -e "s|PLACEHOLDER_SERVICE_ACCOUNT|$SERVICE_ACCOUNT|g" \
    cloudrun.yaml > service.yaml

# Perform a dry-run.
echo "Dry-Run:"
gcloud run services replace service.yaml --project="$PROJECT_ID" --region="$REGION" --dry-run
if [[ $? -ne 0 ]]; then
  echo "Dry-run failed. Check the gcloud output and your environment variables."
  exit 1
fi

echo ""
echo "Dry-run successful.  Deploy? [Y/n]"
read -r response
if [[ "$response" =~ ^[Yy]$ ]]; then
  echo "Deploying..."
  gcloud run services replace service.yaml --project="$PROJECT_ID" --region="$REGION"
  if [[ $? -ne 0 ]]; then
    echo "Deployment failed. Check the gcloud output."
    exit 1
  fi
  echo "Deployment successful!"
  echo "Make a request using the following command:"
  echo "curl -H \"Authorization: Bearer \$(gcloud auth print-identity-token)\" $(gcloud run services describe "$SERVICE_NAME" --project="$PROJECT_ID" --region="$REGION" --format='value(status.url)')"
else
  echo "Deployment cancelled."
  echo "==Deploy yourself using the following command=="
  echo "gcloud run services replace service.yaml --project=\"$PROJECT_ID\" --region=\"$REGION\""
fi
