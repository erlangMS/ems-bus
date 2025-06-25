FROM ubuntu:22.04

# Definições globais de ambiente
ENV LANG=pt_BR.UTF-8 \
    LANGUAGE=pt_BR:pt:en \
    LC_ALL=pt_BR.UTF-8 \
    TZ=America/Sao_Paulo \
    DEBIAN_FRONTEND=noninteractive

# Copia arquivos da aplicação e dependências
COPY ems-bus-2.0.11.tar.gz /tmp/
COPY odbcinst.ini /etc/odbcinst.ini

# Instala pacotes, configura ambiente, extrai app e limpa
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    apt-utils \
    locales \
    tzdata \
    curl \
    wget \
    zip \
    unzip \
    net-tools \
    unixodbc \
    tdsodbc \
    freetds-common \
    odbcinst1debian2 \
    odbcinst \
    libcppdb-sqlite3-0 \
    libodbc1 \
    libiodbc2 \
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
    mkdir -p /var/opt/erlangms/{log,archive_log} \
             /var/log/erlangms/db \
             /app && \
    tar -xzf /tmp/ems-bus-2.0.11.tar.gz -C /app --strip-components=1 && \
    ln -sf /app/priv/conf/odbc.ini /root/.odbc.ini && \
    ln -sf /app/priv/conf/odbc.ini /etc/odbc.ini && \
    rm -f /tmp/ems-bus-2.0.11.tar.gz && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

# Define diretório de trabalho
WORKDIR /app

# Expõe portas
EXPOSE 2301 2389

# Comando padrão
CMD [ "/app/bin/ems-bus", "console" ]
