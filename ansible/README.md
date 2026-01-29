# Provisionamento com Ansible

Este diretório contém os playbooks e configurações do Ansible para provisionar o ambiente de build do **ErlangMS**.

## Pré-requisitos

Certifique-se de ter o Ansible instalado em sua máquina local:

```bash
# Ubuntu/Debian
sudo apt update
sudo apt install ansible
```

### Instalar dependências para o Ansible

```bash
ansible-galaxy install -r requirements.yml
```

## Como Executar

Para aplicar o provisionamento em todos os hosts definidos no inventário:

```bash
ansible-playbook -i inventory.ini playbooks/playbook-erlangms.yml
```

