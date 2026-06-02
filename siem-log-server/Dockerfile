# Use a slim Python base image
FROM python:3.11-slim

# Install system dependencies needed for compiling certain packages and Matplotlib
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy requirements list first to utilize Docker caching
COPY requirements.txt .

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application server code
COPY . .

# Expose the port your Flask app runs on
EXPOSE 5000

# Run the server using Gunicorn for production stability
CMD ["python", "server.py"]