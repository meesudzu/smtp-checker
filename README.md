# SMTP Checker

A standalone, single-file PHP server to test standard SMTP and AWS SES (IAM Keys) connections. It's built to be easily deployed to **Google Cloud Run**.

## Deployment to Google Cloud Run

This project includes a `Dockerfile` and `cloudbuild.yaml` to deploy directly to Cloud Run using Google Cloud Build. Follow the steps below:

### Prerequisites
1. You must have the [Google Cloud CLI (`gcloud`)](https://cloud.google.com/sdk/docs/install) installed and initialized.
2. Ensure you are authenticated and your target project is set:
   ```bash
   gcloud auth login
   gcloud config set project YOUR_PROJECT_ID
   ```
3. Enable the required Google Cloud APIs for your project:
   ```bash
   gcloud services enable cloudbuild.googleapis.com run.googleapis.com artifactregistry.googleapis.com
   ```

### Step-by-Step Deployment

1. **Configure Artifact Registry (Optional but Recommended)**
   If you don't already have an Artifact Registry repository for Docker images, create one:
   ```bash
   gcloud artifacts repositories create smtp \
       --repository-format=docker \
       --location=asia-southeast1 \
       --description="Docker repository for SMTP Checker"
   ```

2. **Submit the Build and Deploy**
   Run the following command from the root of this project (where the `cloudbuild.yaml` file is located). This command will trigger Cloud Build to build the Docker image and deploy it to Cloud Run.
   
   ```bash
   gcloud builds submit
   ```

3. **Access Your Application**
   Once the deployment is complete, `gcloud` will output the URL of your new Cloud Run service. It will look something like this:
   `https://smtp-checker-xxxxxxxx-xs.a.run.app`

   Click the link to open your SMTP Checker!

## Local Development

If you want to test the server locally without Docker, simply use PHP's built-in web server:

```bash
php -S localhost:8080 index.php
```
Then open `http://localhost:8080` in your browser.
