FROM python:3.12-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

ENV PORT=9999
EXPOSE 9999

# gunicorn: long timeout because live LLM calls can take 60-180s
CMD ["gunicorn", "-b", "0.0.0.0:9999", "-w", "4", "-t", "360", "app:app"]
