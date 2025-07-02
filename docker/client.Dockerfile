# Use an official Python runtime as a parent image
FROM python:3.9-slim

# Set the working directory in the container
WORKDIR /app

# Copy the requirements file into the container at /app
COPY requirements.txt .

# Install any needed packages specified in requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Copy the src directory into the container at /app/src
COPY src/ /app/src/

# Default command to run the client
# Configuration path is relative to the WORKDIR or an absolute path mounted as a volume.
# Expects config and certs to be mounted at /app/config and /app/certs respectively by docker-compose.
CMD ["python", "src/client.py", "--config", "config/client_config.yaml"]
