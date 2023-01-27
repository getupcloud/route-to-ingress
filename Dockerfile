FROM python:3.10
RUN pip install kubernetes
ADD . /app
WORKDIR /app
CMD python3 /app/app.py
