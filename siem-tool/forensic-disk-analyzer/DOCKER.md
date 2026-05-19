# Forensic Disk Analyzer - Docker Setup

Docker allows you to run the Forensic Disk Analyzer without installing dependencies on your host machine.

## Prerequisites

- [Docker](https://docs.docker.com/get-docker/) installed
- [Docker Compose](https://docs.docker.com/compose/install/) installed

## Quick Start

### 1. Prepare Your Files

Create two directories in the `forensic-disk-analyzer` folder:

```bash
cd siem-tool/forensic-disk-analyzer
mkdir -p input output
```

Place your disk image in the `input` folder. Supported formats:
- `.dd` (raw image)
- `.E01` (EnCase)
- `.iso`

### 2. Build the Docker Image

```bash
docker-compose build
```

### 3. Run the Analyzer

```bash
docker-compose up
```

Results will be stored in the `output` folder.

## Usage Examples

### Basic Analysis

```bash
# Mount your disk image to input folder, then run:
docker-compose up
```

### With Custom Image Filename

If your image file has a different name, edit the command in `docker-compose.yml`:

```yaml
command: >
  python run_forensic_pipeline.py
  /input/your-image.dd
  /output
```

### Interactive Mode

```bash
docker-compose run --rm forensic-analyzer /bin/bash
```

### Using Docker Commands Directly

```bash
# Build
docker build -t forensic-analyzer ./backend

# Run
docker run --rm \
  -v $(pwd)/input:/input:ro \
  -v $(pwd)/output:/output \
  -w /app \
  forensic-analyzer \
  python run_forensic_pipeline.py /input/disk.dd /output
```

## Output

Results are saved to the `output` directory:

- `extraction_summary.json` - Extracted artifacts summary
- `layered_analysis_results.json` - Correlation analysis results
- `timestomp_report.*` - Timestomp detection reports (txt, json, csv, html)
- `advanced_antiforensic_results.json` - Anti-forensic detection results
- `preprocessed_for_ai.json` - AI analysis ready data

## Security Notes

The container runs with:
- `SYS_RAWIO` capability (required for disk analysis)
- `seccomp:unconfined` (needed for raw device access)

For production use, consider restricting these privileges.

## Troubleshooting

### Permission Denied

If you encounter permission issues:

```bash
sudo chown -R $(id -u):$(id -g) output/
```

### Out of Memory

Add memory limits in docker-compose.yml:

```yaml
deploy:
  resources:
    limits:
      memory: 4G
```

## Clean Up

```bash
# Stop containers
docker-compose down

# Remove built images
docker-compose down --rmi local
```
