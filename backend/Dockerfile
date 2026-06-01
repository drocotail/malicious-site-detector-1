FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# ML 모델 자동 학습 (모델 파일이 없을 때만)
RUN python -c "import os; os.path.exists('app/ml/saved_model/phishing_model.pkl') or __import__('subprocess').run(['python', '-m', 'app.ml.auto_train'], check=False)"

EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
