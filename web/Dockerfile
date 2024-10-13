FROM python:3.9-alpine

RUN apk update && apk add --no-cache nginx

WORKDIR /app

COPY requirements.txt requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY . .


COPY start.sh /start.sh
RUN chmod +x /start.sh

# Expose ports  for listening
EXPOSE 1234
# Start Supervisor to manage processes
CMD ["/start.sh"]  