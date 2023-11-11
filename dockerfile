FROM python:alpine
WORKDIR /app
COPY main.py /app/
RUN pip install requests beautifulsoup4 pyTelegramBotAPI
CMD ["sh", "-c", "python main.py $API_KEY"]
