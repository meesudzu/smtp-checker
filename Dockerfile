FROM php:8.2-cli

# Copy application code
WORKDIR /var/www/html
COPY index.php .

# The PORT environment variable is provided by Cloud Run
ENV PORT=8080

# Start PHP built-in web server
CMD [ "sh", "-c", "php -S 0.0.0.0:${PORT} index.php" ]
