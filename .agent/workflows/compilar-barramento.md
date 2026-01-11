---
description: Compilar o barramento e gerar release
---

# Workflow: Compilar o Barramento ErlangMS

Este workflow compila o barramento ErlangMS, gera a release e coloca o arquivo tar.gz na pasta correta do projeto unb_servicos.

## Passos

1. Navegar para o diretório do projeto ems-bus
```bash
cd /dados/desenvolvimento/unb/erlangms/ems-bus
```

// turbo
2. Executar o script de release (sem build da imagem Docker)
```bash
./rel/release.sh --skip-build-image
```

// turbo
3. Mover o arquivo gerado para a pasta barramento do projeto unb_servicos e renomear
```bash
mv barramento/ems-bus-*.tar.gz /dados/desenvolvimento/unb/unb_servicos/barramento/ems-bus.tar.gz
```

// turbo
4. Remover a pasta barramento temporária
```bash
rmdir barramento
```

// turbo
5. Verificar que o arquivo foi criado corretamente
```bash
ls -lh /dados/desenvolvimento/unb/unb_servicos/barramento/ems-bus.tar.gz
```

## Notas

- O script `release.sh` já executa o `build.sh` internamente, então não é necessário compilar separadamente
- A versão do barramento é definida em `src/ems_bus.app.src`
- O arquivo final deve estar em `/dados/desenvolvimento/unb/unb_servicos/barramento/ems-bus.tar.gz`
- Durante a compilação podem aparecer warnings sobre funções indefinidas, mas isso é normal
