FROM php:7.4-apache

RUN apt-get update && apt-get install -y --no-install-recommends \
    libzip-dev \
    zip \
    cron \
    && docker-php-ext-install zip \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

RUN a2enmod rewrite \
    && echo "ServerName localhost" >> /etc/apache2/apache2.conf

RUN cat <<EOF > /etc/apache2/conf-available/security-headers.conf
<IfModule mod_headers.c>
    Header set X-Content-Type-Options "nosniff"
    Header set X-Frame-Options "SAMEORIGIN"
    Header set X-XSS-Protection "1; mode=block"
    Header set Content-Security-Policy "default-src 'self'; img-src 'self' data:; style-src 'self';"
</IfModule>
EOF

RUN a2enconf security-headers

COPY . /var/www/html/

RUN mkdir -p /var/www/html/uploads /var/log/php \
    && touch /var/log/php/php_errors.log \
    && touch /var/www/html/user_data.json \
    && chown -R www-data:www-data /var/www/html /var/log/php \
    && chmod -R 755 /var/www/html \
    && chmod 755 /var/www/html/uploads \
    && chmod 666 /var/www/html/user_data.json \
    && chmod 600 /var/log/php/php_errors.log

COPY init-users.sh /docker-entrypoint.d/
RUN chmod +x /docker-entrypoint.d/init-users.sh

ENV FLAG="nite{fake_flag}"

EXPOSE 80

RUN echo '#!/bin/bash\n\
    rm -rf /var/www/html/uploads/\n\
    mkdir /var/www/html/uploads/\n\
    cp /var/www/html/user_data_bak.json /var/www/html/user_data.json\n' > /maintenance.sh \
    && chmod +x /maintenance.sh

RUN echo "*/30 * * * * /maintenance.sh" > /etc/cron.d/maintenance-cron \
    && chmod 0644 /etc/cron.d/maintenance-cron \
    && crontab /etc/cron.d/maintenance-cron

CMD /docker-entrypoint.d/init-users.sh && service cron start && apache2-foreground
