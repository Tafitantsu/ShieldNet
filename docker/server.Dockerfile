# Use an official Python runtime as a parent image
FROM python:3.9-slim

# Set the working directory in the container
WORKDIR /app

# Copy the requirements file into the container at /app
COPY ../requirements.txt .
# Install any needed packages specified in requirements.txt
# python-dotenv will be installed from requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Copy the server application code
# Assuming client/common is also needed by server for env_config_loader, logging_setup, network_utils
# This might need adjustment based on final project structure. If common is truly shared,
# copying ../client/common might be needed or a shared 'common' dir at project root.
# For now, let's assume server.py can reach client/common via Python's path or it's mirrored.
COPY ../server /app/server
COPY ../client/common /app/client/common # Copy common utilities

# Default command to run the server
# The --config argument now points to the .env file.
# This .env file is expected to be mounted via docker-compose.yml.
CMD ["python", "server/server.py", "--config", "/app/config/.env"]
