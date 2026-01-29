# Instruções de Build no ErlangMS

Este documento descreve como realizar o build do projeto dentro da máquina virtual (VM) configurada pelo Vagrant.

## 1. Subir e Acessar a Máquina Virtual

A partir da raiz do projeto, execute os seguintes comandos:

```bash
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

Arquivos gerados:
- `ems-bus-2.x.x.tar.gz`
- `ems-bus.tar.gz`

