# -*- mode: ruby -*-
# vi: set ft=ruby :

# Descrição: Provisiona máquina com Erlang/OTP para build
# Data: 24/06/2025
# Autor: Everton de Vargas Agilar

Vagrant.configure("2") do |config|
  config.vm.define "erlangms" do |node|
    node.vm.box = "generic/ubuntu2204"
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

    # Provisionamento via Ansible
    node.vm.provision "ansible" do |ansible|
      ansible.inventory_path = "ansible/inventory.ini"
      ansible.config_file = "ansible/ansible.cfg"
      ansible.playbook = "ansible/playbooks/playbook-erlangms.yml"
    end
  end
end
