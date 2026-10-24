# PHP Posture Scanner — production image
# php:8.3-apache ships curl, json, mbstring and openssl built in.
FROM php:8.3-apache

# Serve from public/ and enable URL rewriting.
ENV APACHE_DOCUMENT_ROOT=/var/www/html/public
RUN sed -ri -e 's!/var/www/html!${APACHE_DOCUMENT_ROOT}!g' /etc/apache2/sites-available/*.conf \
 && sed -ri -e 's!/var/www/!${APACHE_DOCUMENT_ROOT}!g' /etc/apache2/apache2.conf /etc/apache2/conf-available/*.conf \
 && a2enmod rewrite headers \
 && printf '<Directory ${APACHE_DOCUMENT_ROOT}>\n  AllowOverride All\n  Require all granted\n  FallbackResource /index.php\n</Directory>\n' > /etc/apache2/conf-available/pvc.conf \
 && a2enconf pvc

# Production PHP settings: hide the version, don't display errors.
RUN { \
      echo 'expose_php=Off'; \
      echo 'display_errors=Off'; \
      echo 'log_errors=On'; \
      echo 'memory_limit=128M'; \
      echo 'max_execution_time=30'; \
    } > /usr/local/etc/php/conf.d/pvc.ini

COPY . /var/www/html
RUN chown -R www-data:www-data /var/www/html

# Many PaaS hosts inject $PORT; default to 8080. Apache 2.4 substitutes ${PORT}
# from the process environment, and sourcing it in envvars guarantees it is set.
ENV PORT=8080
RUN sed -ri 's/Listen 80$/Listen ${PORT}/' /etc/apache2/ports.conf \
 && sed -ri 's/:80>/:${PORT}>/' /etc/apache2/sites-available/000-default.conf \
 && echo 'export PORT=${PORT:-8080}' >> /etc/apache2/envvars
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD curl -fsS "http://127.0.0.1:${PORT}/?health=1" || exit 1
