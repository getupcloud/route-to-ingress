FROM python:3.10
RUN pip install kubernetes
ADD . /app
WORKDIR /app
ENTRYPOINT ["python3", "/app/app.py"]
