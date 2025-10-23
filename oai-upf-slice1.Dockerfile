# Dockerfile for oai-upf-slice1
# This Dockerfile is based on the information from the README.md and docker-compose.yaml.
# It assumes a base OAI UPF image. Since the base image is not available,
# this Dockerfile starts from a generic Ubuntu image and installs the dependencies
# for the Anomaly Detection Server.

# In a real scenario, this would be the OAI UPF base image.
FROM ubuntu:20.04

# Set non-interactive frontend for apt-get
ENV DEBIAN_FRONTEND=noninteractive

# Install Python, pip, and other dependencies for scapy
RUN apt-get update && \
    apt-get install -y python3 python3-pip tcpdump && \
    rm -rf /var/lib/apt/lists/*

# Install required Python libraries for the Anomaly Detection Server
RUN pip3 install pandas scikit-learn==1.5.0 numpy joblib scapy

# Copy the Anomaly Detection Server script and the trained models into the container.
# The paths inside the container are assumed to be at the root.
COPY anomaly-detection-server-slice1.py /anomaly-detection-server-slice1.py
COPY notebooks/random_forest_model.pkl /random_forest_model.pkl
COPY notebooks/preprocessor.pkl /preprocessor.pkl

# The original image ttsourdinis/custom-upf:slice1 would have its own
# CMD or ENTRYPOINT to start the UPF service.
# The anomaly detection server is started manually via `docker exec`,
# as per the instructions in README.md.
# For example, the base image might have:
# CMD ["/openair-upf/bin/oai_upf", "-c", "/openair-upf/etc/config.yaml"]
