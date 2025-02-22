# Deploying the hello-world-with-sidecar Cloud Run Service

This service includes a main application container (using the public `hello-app` image) and a sidecar container for network traffic capture.  The service name and sidecar environment variables are set via environment variables and substituted into a `service.yaml` file before deployment. The service requires authentication.

## Prerequisites

*   A Google Cloud project with billing enabled.
*   The Google Cloud SDK installed and configured.
*   A GCS bucket for storing pcap files.

## Configuration

1.  **Create a GCS bucket** to store the captured network traffic.

2.  **Clone this repository:**

    ```bash
    git clone [YOUR_REPOSITORY_URL]  # Replace with your repository URL
    cd [YOUR_REPOSITORY_DIRECTORY]   # Replace with your repository directory
    ```

3.  **Set Environment Variables:**

    **Before running the preparation script, you *must* set the following environment variables in your shell:**

    ```bash
    export PCAP_GCS_BUCKET="your-gcs-bucket"  # REPLACE with your GCS bucket name
    export PCAP_FILTER="tcp port 8080"        # REPLACE with your desired PCAP filter
    export PCAP_IFACE="eth0"                # REPLACE if necessary (default is eth0)
    export PCAP_JSON_LOG="true"             # REPLACE with "false" if you don't want JSON logs
    export PROJECT_ID="your-gcp-project-id"     # REPLACE with your Google Cloud project ID
    export SERVICE_NAME="hello-world-with-sidecar"  # REPLACE with your desired service name
    export REGION="us-central1"                 # REPLACE if necessary (default is us-central1)
    ```

    **Important:** The `prepare_and_dry_run.sh` script uses these environment variables. If they are not set, the script will generate an incorrect `service.yaml` file.

4. **Review `cloudrun.yaml` (Optional):**

    The `cloudrun.yaml`file is a template containing placeholders for the environment variables. The `prepare_and_dry_run.sh` script replaces these placeholders.  The `service.yaml` file contains the configuration that will be sent to the Cloud Run.
    ```yaml
    apiVersion: serving.knative.dev/v1
    kind: Service
    metadata:
      name: PLACEHOLDER_SERVICE_NAME
      annotations:
        [run.googleapis.com/ingress](https://www.google.com/search?q=http://run.googleapis.com/ingress): all
        [run.googleapis.com/ingress-status](https://www.google.com/search?q=http://run.googleapis.com/ingress-status): all
        [run.googleapis.com/launch-stage](https://www.google.com/search?q=http://run.googleapis.com/launch-stage): BETA
        [run.googleapis.com/cpu-throttling](https://www.google.com/search?q=http://run.googleapis.com/cpu-throttling): "true"
    spec:
      template:
        metadata:
          annotations:
            [run.googleapis.com/execution-environment](https://www.google.com/search?q=http://run.googleapis.com/execution-environment): gen2
        spec:
          containers:
          - image: gcr.io/google-samples/hello-app:1.0
            name: main
            ports:
              - name: http1
                containerPort: 8080
          - image: us-central1-docker.pkg.dev/pcap-sidecar/pcap-sidecar/pcap-sidecar:latest
            name: sidecar
            env:
            - name: PCAP_IFACE
              value: "PLACEHOLDER_PCAP_IFACE"
            - name: PCAP_GCS_BUCKET
              value: "PLACEHOLDER_PCAP_GCS_BUCKET"
            - name: PCAP_FILTER
              value: "PLACEHOLDER_PCAP_FILTER"
            - name: PCAP_JSON_LOG
              value: "PLACEHOLDER_PCAP_JSON_LOG"
            startupProbe:
              tcpSocket:
                port: 12345
              initialDelaySeconds: 5
              periodSeconds: 5
              failureThreshold: 3
            securityContext:
              capabilities:
                add:
                  - NET_ADMIN
                  - NET_RAW
    ```

    **`securityContext` Explanation:**

    The `securityContext` section, specifically within the `sidecar` container definition, is crucial for the packet capture functionality. It grants the sidecar container elevated privileges necessary to access network interfaces:

    *   **`capabilities`:** This field specifies Linux capabilities. Capabilities are a way to grant specific privileges to a process without giving it full root access.
    *   **`add: - NET_ADMIN - NET_RAW`:**
        *   **`NET_ADMIN`:** Allows the container to perform various network-related administrative tasks, such as configuring interfaces and modifying routing tables. This is needed for capturing packets.
        *   **`NET_RAW`:** Allows the container to create and use raw sockets. Raw sockets provide direct access to network packets, bypassing some of the higher-level network stack processing. This is essential for packet capture tools like `tcpdump` (which the sidecar likely uses).

    Without these capabilities, the sidecar container would be unable to access the network interface and capture packets, resulting in errors.
5.  **Review `prepare_and_dry_run.sh`**

    The script takes environment variables to create a `service.yaml` file. The generated `service.yaml` is then used in a dry-run test and outputs the gcloud command to apply the configuration.

    ```bash
    #!/bin/bash

    # Set environment variables (replace with your actual values).
    #  These *must* be set before running this script.
    export PCAP_GCS_BUCKET="your-gcs-bucket"  # REPLACE
    export PCAP_FILTER="tcp port 8080"        # REPLACE
    export PCAP_IFACE="eth0"                # REPLACE (if needed)
    export PCAP_JSON_LOG="true"             # REPLACE (if needed)
    export PROJECT_ID="your-gcp-project-id"     # REPLACE
    export SERVICE_NAME="hello-world-with-sidecar" # REPLACE (if needed)
    export REGION="us-central1"                 # REPLACE (if needed)


    # Create the service YAML file with variable substitutions.
    sed -e "s|PLACEHOLDER_SERVICE_NAME|$SERVICE_NAME|g" \
        -e "s|PLACEHOLDER_PCAP_GCS_BUCKET|$PCAP_GCS_BUCKET|g" \
        -e "s|PLACEHOLDER_PCAP_FILTER|$PCAP_FILTER|g" \
        -e "s|PLACEHOLDER_PCAP_IFACE|$PCAP_IFACE|g" \
        -e "s|PLACEHOLDER_PCAP_JSON_LOG|$PCAP_JSON_LOG|g" \
        cloudrun.yaml > service.yaml

    # Perform a dry-run.
    gcloud run services replace service.yaml --project="$PROJECT_ID" --region="$REGION" --dry-run

    echo ""
    echo "If the dry-run looks good, run the following command to deploy:"
    echo "gcloud run services replace service.yaml --project=\"$PROJECT_ID\" --region=\"$REGION\""
    ```

## Deployment

1.  **Run the preparation and dry-run script:**

    ```bash
    ./prepare_and_dry_run.sh
    ```

    This script will:

    *   Create a `service.yaml` file by substituting the environment variables into `cloudrun.yaml`.
    *   Perform a dry-run of `gcloud run services replace` using the generated `service.yaml`.  **Carefully review the output of the dry-run to ensure everything is correct.**
    *  Print the command required to perform the actual deployment.

2.  **Verify the Dry-Run Output:**

    Thoroughly examine the output of the dry-run.  Make sure the service name, environment variables, region, and other settings are correct.  If anything is wrong, adjust the environment variables and re-run `prepare_and_dry_run.sh`.

3.  **Deploy the Service (if dry-run is successful):**

    If the dry-run output looks correct, copy and paste the `gcloud run services replace` command that was printed by the script and run it.  For example:

    ```bash
    gcloud run services replace service.yaml --project="your-gcp-project-id" --region="us-central1"
    ```

4.  **Verify the deployment:**

    ```bash
    gcloud run services describe "$SERVICE_NAME" --project "$PROJECT_ID" --region "$REGION"
    ```

    You need to have `$PROJECT_ID`, `$SERVICE_NAME`, and `$REGION` exported. This command will show the service details, including the URL.

## Accessing the Service

Once deployed, you can access the service at the URL provided by Cloud Run. **Since the service requires authentication, you will need to use an authenticated request.**

Example using curl and gcloud (replace `$PROJECT_ID`, `$SERVICE_NAME`, and `$REGION` with their corresponding values):

```bash
curl -H "Authorization: Bearer <span class="math-inline">\(gcloud auth print\-identity\-token\)" "</span>(gcloud run services describe "$SERVICE_NAME" --project "$PROJECT_ID" --region "$REGION" --format='value(status.url)')"