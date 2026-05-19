# Cyber Chakshu SIEM - Forensic Disk Analyzer
FROM python:3.11-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    sleuthkit \
    ewf-tools \
    libewf-dev \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy requirements first for better caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create output directory with proper permissions
RUN mkdir -p /output && chown -R 1000:1000 /output

# Create non-root user for security
RUN useradd -m -u 1000 forensicuser && chown -R forensicuser:forensicuser /app
USER forensicuser

# Default command
CMD ["python", "run_forensic_pipeline.py", "--help"]
