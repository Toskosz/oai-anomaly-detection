
# Use an official Python runtime as a parent image
FROM python:3.8-slim

# Set the working directory in the container
WORKDIR /app

# Copy the current directory contents into the container at /app
COPY . /app/

# Install any needed packages specified in requirements.txt
RUN pip install --no-cache-dir scikit-learn pandas scapy joblib

# Define environment variables
ENV XAPP_IP=192.168.70.1
ENV XAPP_PORT=8080

# Run anomaly-detection-server-slice1.py when the container launches
CMD ["python", "-u", "anomaly-detection-server-slice1.py"]
