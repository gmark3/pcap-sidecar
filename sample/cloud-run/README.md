# Deploying the hello-world-with-sidecar Cloud Run Service

This service includes a main application container (using the public `hello-app` image) and a sidecar container for network traffic capture.  The service name and sidecar environment variables are set via environment variables and substituted into a `service.yaml` file before deployment. The service requires authentication.

## Prerequisites

*   A Google Cloud project with billing enabled.
*   The Google Cloud SDK installed and configured.
*   A GCS bucket for storing pcap files.

## Configuration

1.  **Create a GCS bucket** to store the captured network traffic.

    Configure Cloud Storage Bucket for PCAP file upload. Give the runtime service account the `roles/storage.admin` role on the bucket so that it may create objects and read bucket metadata.

3.  **Set Environment Variables:**

    **Before running the preparation script, you *must* set the following environment variables in your shell:**


    ```bash
    # Set environment variables (replace with your actual values).
    #  These *must* be set before running this script.
    export PCAP_GCS_BUCKET="your-gcs-bucket"  # REPLACE
    export PROJECT_ID="your-gcp-project-id"     # REPLACE
    export SERVICE_NAME="hello-world-with-sidecar" # REPLACE (if needed)
    export REGION="us-central1"                 # REPLACE (if needed)
    ```

    **Important:** The `prepare_and_dry_run.sh` script uses these environment variables. If they are not set, the script will generate an incorrect `service.yaml` file.

4. **Review `cloudrun.yaml` (Optional):**

    The `cloudrun.yaml`file is a template containing placeholders for the environment variables. The `prepare_and_dry_run.sh` script replaces these placeholders.  The `service.yaml` file contains the configuration that will be sent to the Cloud Run.

 
5.  **Review `prepare_and_dry_run.sh`**

    The script takes environment variables to create a `service.yaml` file. The generated `service.yaml` is then used in a dry-run test and outputs the gcloud command to apply the configuration.


## Deployment

1.  **Run the preparation and dry-run script:**

    ```bash
    ./prepare_and_dry_run.sh
    ```

    This script will:

    *   Create a `service.yaml` file by substituting the environment variables into `cloudrun.yaml`.


2.  **Verify the Dry-Run Output:**

    Thoroughly examine the `service.yaml` output from the dry-run.  Make sure the service name, environment variables, region, and other settings are correct.  If anything is wrong, adjust the environment variables and re-run `prepare_and_dry_run.sh`.

3.  **Deploy the Service (if dry-run is successful):**

    If the dry-run output looks correct, copy and paste the `gcloud run services replace` command that was printed by the script and run it.  For example:

    ```bash
    gcloud run services replace service.yaml --project="your-gcp-project-id" --region="us-central1"
    ```

## Accessing the Service

Once deployed, you can access the service at the URL provided by Cloud Run. **Since the service requires authentication, you will need to use an authenticated request.**

Example using curl and gcloud (replace `$PROJECT_ID`, `$SERVICE_NAME`, and `$REGION` with their corresponding values):

```bash
curl -H "Authorization: Bearer $(gcloud auth print-identity-token)" $(gcloud run services describe "$SERVICE_NAME" --project "$PROJECT_ID" --region "$REGION" --format='value(status.url)')
```

## Clean Up

Once you have finished, delete the service you had created in the prior steps

```bash
gcloud run services delete $SERVICE_NAME --project="$PROJECT_ID" --region="$REGION"
```

  * Delete PCAP files generated in your Cloud Storage Bucket