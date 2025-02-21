# Cloud Run Deployment with Sidecar

This README provides instructions for deploying a Cloud Run service with a sidecar container, using a YAML configuration file and a bash script.

## Prerequisites

* Google Cloud SDK (gcloud) installed and configured.
* Docker installed (if you need to build or push your sidecar image).
* A Google Cloud project with Cloud Run API enabled.
* A Docker registry (e.g., Google Container Registry or Artifact Registry) to store your sidecar image.

## Files

* `cloudrun.yaml`: The YAML configuration file for your Cloud Run service.
* `deploy.sh`: A bash script to set environment variables and deploy the service.

## Instructions

1.  **Create `cloudrun.yaml`:**

    Copy and paste the following YAML content into a file named `cloudrun.yaml`:

    ```yaml
    apiVersion: serving.knative.dev/v1
    kind: Service
    metadata:
      name: hello-world-with-sidecar
      annotations:
        [run.googleapis.com/client-name](https://www.google.com/search?q=https://run.googleapis.com/client-name): cloud-console
    spec:
      template:
        spec:
          containers:
          - image: gcr.io/google-samples/hello-app:1.0
            ports:
            - containerPort: 8080
          - image: us-central1-docker.pkg.dev/pcap-sidecar/pcap-sidecar/pcap-sidecar:latest
            name: sidecar
            ports:
            - containerPort: 12345
            startupProbe:
              tcpSocket:
                port: 12345
              periodSeconds: 10
              failureThreshold: 3
              successThreshold: 1
              initialDelaySeconds: 15
            env:
            - name: PCAP_IFACE
              value: "${PCAP_IFACE}"
            - name: PCAP_GCS_BUCKET
              value: "${PCAP_GCS_BUCKET}"
            - name: PCAP_FILTER
              value: "${PCAP_FILTER}"
            - name: PCAP_JSON_LOG
              value: "${PCAP_JSON_LOG}"
          containerConcurrency: 80
          timeoutSeconds: 300
      traffic:
      - latestRevision: true
        percent: 100
      annotations:
        [run.googleapis.com/ingress](https://www.google.com/search?q=https://run.googleapis.com/ingress): all
        [run.googleapis.com/ingress-allow-all](https://www.google.com/search?q=https://run.googleapis.com/ingress-allow-all): "true"
        [run.googleapis.com/launch-stage](https://www.google.com/search?q=https://run.googleapis.com/launch-stage): BETA
        [run.googleapis.com/client-name](https://www.google.com/search?q=https://run.googleapis.com/client-name): cloud-console
        [run.googleapis.com/cpu-throttling](https://www.google.com/search?q=https://run.googleapis.com/cpu-throttling): "true"
        [run.googleapis.com/vpc-access-egress](https://www.google.com/search?q=https://run.googleapis.com/vpc-access-egress): all
        [run.googleapis.com/vpc-access-connector](https://www.google.com/search?q=https://run.googleapis.com/vpc-access-connector): "" #Fill in if you are using a VPC connector.
        [run.googleapis.com/service-account](https://www.google.com/search?q=https://run.googleapis.com/service-account): "${SERVICE_ACCOUNT}" #Use the bash variable
    ```

2.  **Create `deploy.sh`:**

    Copy and paste the following bash script into a file named `deploy.sh`:

    ```bash
    #!/bin/bash

    export PCAP_IFACE="your_interface"
    export PCAP_GCS_BUCKET="your_bucket"
    export PCAP_FILTER="your_filter"
    export PCAP_JSON_LOG="true" # or "false"
    export SERVICE_ACCOUNT="your-service-account@your-project.iam.gserviceaccount.com" #replace with your service account.
    export YOUR_REGION="us-central1" #replace with your region

    gcloud run deploy --image gcr.io/google-samples/hello-app:1.0 --platform managed --region ${YOUR_REGION} --source cloudrun.yaml
    ```

3.  **Replace Placeholders:**

    * In `deploy.sh`, replace the following placeholders with your actual values:
        * `"your_interface"`
        * `"your_bucket"`
        * `"your_filter"`
        * `"your-service-account@your-project.iam.gserviceaccount.com"`
        * `"us-central1"` (or your desired region)

4.  **Make `deploy.sh` Executable:**

    Open your terminal and run the following command:

    ```bash
    chmod +x deploy.sh
    ```

5.  **Run the Deployment Script:**

    Execute the script:

    ```bash
    ./deploy.sh
    ```

6.  **VPC Connector (Optional):**

    If you are using a VPC connector, replace the empty string in the `vpc-access-connector` annotation in `cloudrun.yaml` with the name of your VPC connector.

7.  **Service Account (Optional):**
    If you do not wish to use a service account, you can remove the `run.googleapis.com/service-account` annotation from the cloudrun.yaml file.

## Notes

* Ensure that your sidecar image is accessible from Cloud Run.
* Adjust the `containerConcurrency` and `timeoutSeconds` values in `cloudrun.yaml` as needed for your application.
* Adjust the startupProbe values as needed for your sidecar application.
* Feel free to adjust the ingress settings in the cloudrun.yaml to suit your needs.