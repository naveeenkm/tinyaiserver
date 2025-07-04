# Step 1: Use an official Python base image
FROM python:3.12-slim

# Step 2: Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Step 3: Set working directory
WORKDIR /app

# Step 4: Install dependencies
COPY requirements.txt .
RUN pip install --upgrade pip
RUN pip install -r requirements.txt

# Step 5: Copy project files
COPY . .

# Step 6: Collect static files (if using whitenoise or similar)
# RUN python manage.py collectstatic --noinput

# Step 7: Expose the port (default 8000 for Django)
EXPOSE 8000

# Step 8: Run the server
CMD ["python", "manage.py", "runserver", "0.0.0.0:8000"]
