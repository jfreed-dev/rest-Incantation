FROM python:3.11-slim

WORKDIR /app

# Install dependencies (runtime + test toolchain; the test service runs pytest)
COPY requirements.txt requirements-dev.txt ./
RUN pip install --no-cache-dir -r requirements-dev.txt

# Copy application code
COPY . .

# Set Flask app
ENV FLASK_APP=app.py

# Expose Flask port
EXPOSE 5000

# Default command runs the app (bind to 0.0.0.0 for container access)
CMD ["flask", "run", "--host=0.0.0.0"]
