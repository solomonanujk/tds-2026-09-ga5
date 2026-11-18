FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY main.py ./
COPY ga5 ./ga5
ENV PORT=7860 FASTEMBED_CACHE=/app/.fastembed
# Bake the embedding model into the image.
RUN python -c "from ga5 import rag; assert rag.DENSE.ok, rag.DENSE.error"
CMD ["sh","-c","uvicorn main:app --host 0.0.0.0 --port ${PORT:-7860}"]
