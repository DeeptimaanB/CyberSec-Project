# Use an official PHP image
FROM php:apache

# Install PDO MySQL extension
RUN docker-php-ext-install pdo pdo_mysql

# Enable PDO MySQL extension
RUN docker-php-ext-enable pdo_mysql

# Copy your PHP application into the container
COPY . /var/www/html