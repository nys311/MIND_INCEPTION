FROM python:3.12-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

ENV PORT=9999
EXPOSE 9999

# Single worker + threads: the async benchmark keeps job state in-process, so it
# must not be split across workers. Threads give concurrency (poll while a job
# runs). Long timeout because live LLM calls can take 60-180s.
CMD ["gunicorn", "-b", "0.0.0.0:9999", "-w", "1", "--threads", "8", "-t", "360", "app:app"]
