FROM python:3.10
RUN pip install kubernetes
ADD . /app
CMD python3 /app/main.py
