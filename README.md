# SMTP Checker

A standalone, single-file PHP tool to test standard SMTP and AWS SES (IAM Keys) connections.

## Run with Docker

### Build the image

```bash
docker build -t smtp-checker .
```

### Run the container

```bash
docker run -p 8080:8080 smtp-checker
```

Then open [http://localhost:8080](http://localhost:8080) in your browser.

### Custom port

```bash
docker run -p 9000:9000 -e PORT=9000 smtp-checker
```

## Local Development (without Docker)

Use PHP's built-in web server:

```bash
php -S localhost:8080 index.php
```

Then open [http://localhost:8080](http://localhost:8080) in your browser.
