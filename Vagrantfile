# -*- mode: ruby -*-
# vi: set ft=ruby :

# Descrição: Provisiona máquina com Erlang/OTP para build
# Data: 24/06/2025
# Autor: Everton de Vargas Agilar

Vagrant.configure("2") do |config|
  config.vm.define "erlangms" do |node|
    node.vm.box = "bento/ubuntu-24.04"
    node.vm.hostname = "erlangms"
    node.vm.network "private_network", ip: "192.168.60.10"

    # Compartilha a pasta atual com a VM
    node.vm.synced_folder ".", "/vagrant", type: "virtualbox"

    # Configuração para VirtualBox
    node.vm.provider "virtualbox" do |vb|
      vb.name = "erlangms"
      vb.memory = "1024"
      vb.cpus = "1"
    end

    # Configuração para Libvirt
    node.vm.provider "libvirt" do |lv|
      lv.memory = "1024"
      lv.cpus = "1"
    end

    # Provisionamento via Ansible (Local na VM para total isolamento)
    node.vm.provision "ansible_local" do |ansible|
      ansible.galaxy_role_file = "ansible/requirements.yml"
      ansible.galaxy_roles_path = "/home/vagrant/.ansible/roles"
      ansible.galaxy_command = "ansible-galaxy install --role-file=%{role_file} --roles-path=%{roles_path}"
      ansible.inventory_path = "ansible/inventory.ini"
      ansible.config_file = "ansible/ansible.cfg"
      ansible.playbook = "ansible/playbooks/playbook-erlangms.yml"
    end
  end
end
