FROM python:3.11-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt pytest-cov

# Copy application code
COPY . .

# Expose Flask port
EXPOSE 5000

# Default command runs the app
CMD ["python", "app.py"]
