FROM ubuntu:24.04

# Definições globais de ambiente
ENV LANG=pt_BR.UTF-8 \
    LANGUAGE=pt_BR:pt:en \
    LC_ALL=pt_BR.UTF-8 \
    TZ=America/Sao_Paulo \
    DEBIAN_FRONTEND=noninteractive

# Renomeia usuário e grupo ubuntu para erlangms
RUN groupmod -n erlangms ubuntu && \
    usermod -l erlangms -d /opt/erlangms -m ubuntu

# Instala dependências básicas
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    wget \
    curl \
    ca-certificates && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Instala Microsoft ODBC Driver 17 para SQL Server
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    gnupg2 \
    apt-transport-https && \
    curl https://packages.microsoft.com/keys/microsoft.asc | apt-key add - && \
    curl https://packages.microsoft.com/config/ubuntu/22.04/prod.list > /etc/apt/sources.list.d/mssql-release.list && \
    apt-get update && \
    ACCEPT_EULA=Y apt-get install -y msodbcsql17 && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* && \
    ln -sf /opt/microsoft/msodbcsql17/lib64/libmsodbcsql-17.*.so.*.* /opt/microsoft/msodbcsql17/lib64/libmsodbcsql-17.so

# Instala dependências do barramento
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    apt-utils \
    locales \
    tzdata \
    zip \
    unzip \
    unixodbc \
    tdsodbc \
    freetds-common \
    odbcinst \
    libcppdb-sqlite3-0 \
    libcppdb-odbc0 \
    libltdl7 \
    libcppdb0 \
    ldap-utils \
    odbc-postgresql && \
    sed -i 's/^# *pt_BR.UTF-8 UTF-8/pt_BR.UTF-8 UTF-8/' /etc/locale.gen && \
    locale-gen && \
    update-locale LANG=pt_BR.UTF-8 LANGUAGE=pt_BR:pt:en && \
    ln -sf /usr/share/zoneinfo/America/Sao_Paulo /etc/localtime && \
    echo "America/Sao_Paulo" > /etc/timezone && \
    dpkg-reconfigure --frontend noninteractive tzdata && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Copia e instala o barramento
COPY ./ems-bus.tar.gz /tmp/
RUN mkdir -p /app && \
    tar -xzf /tmp/ems-bus.tar.gz -C /app && \
    ln -sf /app/lib/ems_bus-*/priv /app/priv && \
    rm -f /tmp/ems-bus.tar.gz && \
    mkdir /app/priv/db && \
    chown -R erlangms:erlangms /app && \
    chmod 775 /app/priv/db && \
    echo "'127.0.0.1'." > /app/.hosts.erlang && \
    echo "'127.0.0.1'." > /root/.hosts.erlang && \
    ln -sf /app/priv/conf/odbc.ini /etc/odbc.ini && \
    ln -sf /app/priv/conf/odbcinst.ini /etc/odbcinst.ini

WORKDIR /app

# Expõe portas do barramento
EXPOSE 2301 2344 2389

# Usuário erlangms
USER erlangms

# Health check
HEALTHCHECK --interval=60s --timeout=10s --start-period=60s --retries=3 \
    CMD curl -f http://localhost:2301/ || exit 1

# Inicia o barramento
CMD ["/app/bin/ems_bus", "foreground"]
