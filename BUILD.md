# Instruções de Build no ErlangMS

Este documento descreve como realizar o build do projeto dentro da máquina virtual (VM) configurada pelo Vagrant.

## 1. Subir e Acessar a Máquina Virtual

A partir da raiz do projeto, execute os seguintes comandos:

```bash
# Instalar as dependências
ansible-galaxy install -r ansible/requirements.yml

# Sobe a VM (caso ainda não esteja rodando)
vagrant up

# Acessa a VM via SSH
vagrant ssh
```

## 2. Realizar o Build

Uma vez dentro da VM, o código do projeto está disponível de forma sincronizada na pasta `/vagrant`.

```bash
# Entrar na pasta do projeto
cd /vagrant

# Executar o script de build
./build.sh
```


## 3. Gerar Release

Para gerar o pacote compactado (`.tar.gz`) pronto para distribuição:

```bash
./rel/release.sh
```

O arquivo gerado será algo como `ems-bus-2.x.x.tar.gz` e também uma cópia com nome fixo `ems-bus.tar.gz` na raiz do projeto.

