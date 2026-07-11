FROM php:8.2-cli

RUN apt-get update && apt-get install -y \
    git \
    unzip \
    && rm -rf /var/lib/apt/lists/*

COPY --from=composer:2 /usr/bin/composer /usr/bin/composer

WORKDIR /app

COPY composer.json ./
RUN composer install --no-dev --no-interaction --no-progress

COPY . .

RUN mkdir -p sessions && chmod 777 sessions

EXPOSE 80

CMD ["php", "-S", "0.0.0.0:80", "gateway.php"]
