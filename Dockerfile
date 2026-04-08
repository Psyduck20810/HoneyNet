FROM python:3.11-slim

WORKDIR /honeypot

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create logs directory
RUN mkdir -p logs

# Expose all honeypot ports
# 5000 = Web (Flask), 2222 = SSH honeypot, 27017 = MongoDB honeypot, 2525 = SMTP honeypot
EXPOSE 5000 2222 27017 2525

# Run app
CMD ["python", "app/app.py"]
