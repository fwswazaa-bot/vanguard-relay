FROM php:8.2-cli

WORKDIR /app

COPY composer.json ./
RUN composer install --no-dev --optimize-autoloader

COPY . .

EXPOSE 8080

CMD php -S 0.0.0.0:${PORT:-8080} gateway.php
