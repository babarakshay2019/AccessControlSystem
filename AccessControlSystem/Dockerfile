# Use the official Python image as a base
FROM python:3.9-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

# Set the working directory inside the container
WORKDIR /app

# Install system dependencies
RUN apt-get update \
    && apt-get install -y gcc libpq-dev python3-dev

# Copy the requirements file into the container
COPY requirements.txt /app/

# Install Python dependencies
# RUN pip install --no-cache-dir -r requirements.txt
RUN pip install --timeout=100 --no-cache-dir -r requirements.txt


# Copy the entire project into the container
COPY . /app/

# Expose the port your Django app runs on
EXPOSE 8000

# Set the default command to run the Django app
CMD ["python", "manage.py", "runserver", "0.0.0.0:8000"]
