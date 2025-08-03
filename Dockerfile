## BACKEND ##

# Base image
FROM debian:12-slim

# Metadata
LABEL maintainer="kshitijka"
LABEL version=1.5
LABEL description="Skycrate is a web based file management system that uses Hadoop as filesystem."

# Update & upgrade & install & rm
RUN apt-get update && apt-get upgrade -y && \
    apt-get install -y openjdk-17-jdk && \
    rm -rf /var/lib/apt/lists/* 

# Create non-root user
RUN useradd -s /bin/bash skycrateBack

# Create work dir
RUN mkdir /app
RUN chown -R skycrateBack:skycrateBack /app
COPY ./target/skycrateBackend-0.0.3.jar /app
WORKDIR /app

# Switch user
USER skycrateBack

# Expose port for backend
EXPOSE 8080

CMD ["java", "-jar", "skycrateBackend-0.0.3.jar"]
