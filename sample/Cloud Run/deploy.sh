#!/bin/bash

export PCAP_IFACE="your_interface"
export PCAP_GCS_BUCKET="your_bucket"
export PCAP_FILTER="your_filter"
export PCAP_JSON_LOG="true" # or "false"
export SERVICE_ACCOUNT="your-service-account@your-project.iam.gserviceaccount.com" #replace with your service account.
export YOUR_REGION="us-central1" #replace with your region

gcloud run deploy --image gcr.io/google-samples/hello-app:1.0 --platform managed --region ${YOUR_REGION} --source cloudrun.yaml