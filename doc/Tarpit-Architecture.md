# Arquitetura de Defesa Ativa: Padrão Tarpit no ErlangMS

Este documento detalha o raciocínio arquitetural, os trade-offs e a implementação do mecanismo de **Tarpit** (Poço de Piche) no Barramento ErlangMS.

## 1. O que é um Tarpit?

Na segurança da informação, um Tarpit (ou *Teergrube*) é um serviço de rede que intencionalmente atrasa as conexões de entrada. A premissa central é **inverter a assimetria de custo entre o atacante e o defensor**.

Enquanto a engenharia de software tradicional foca no princípio de *Fail Fast* (falhar rápido e liberar o recurso), essa abordagem otimiza a vida de scripts maliciosos. Um scanner de vulnerabilidade automatizado (como Gobuster, DirBuster ou scripts customizados de fuzzing) depende de respostas rápidas (ex: retornar um erro 404 em 5ms) para testar milhares de URLs ou payloads por segundo usando pouco processamento.

Ao introduzir um atraso intencional de 2 a 30 segundos nas rotas de erro conhecidas por serem vetores de sondagem (sonap), o Tarpit:
1. Reduz drasticamente o *throughput* (vazão) do ataque.
2. Obriga o atacante a abrir milhares de conexões concorrentes se quiser manter a velocidade original.
3. Causa exaustão de *sockets* na máquina do atacante.
4. Torna o ataque ruidoso e facilmente detectável por camadas de infraestrutura (WAF/Firewall) e pelo Rate Limiter da própria aplicação.

## 2. Por que o Tarpit é Incomum na Camada de Aplicação?

Apesar de sua eficácia, a implementação de Tarpits em código de aplicação é rara na indústria. Isso ocorre por três motivos estruturais na engenharia de software moderna:

### A. O Problema do Pool de Threads Bloqueantes
A imensa maioria das aplicações web (Java/Tomcat, Python/Gunicorn, Ruby/Puma, PHP/FPM) utiliza pools de threads ligados aos recursos do Sistema Operacional. Se um servidor possui 200 threads e implementa um `Thread.sleep(30000)` para requisições maliciosas, basta o atacante enviar 200 requisições simultâneas para esgotar o pool de atendimento. O servidor para de responder a usuários legítimos, causando um ataque de Negação de Serviço (DoS) autoinfligido.

### B. Delegação Excessiva para a Infraestrutura de Borda
Existe uma cultura disseminada de delegar a proteção exclusivamente para a borda (Cloudflare, AWS WAF, NGINX). Embora essas ferramentas sejam excelentes para varreduras volumétricas (DDoS na camada de rede), elas não possuem o contexto denso da regra de negócio. Um WAF não sabe que uma URL não catalogada no Barramento dispara um processamento de roteamento interno mais caro que um endpoint estático. O Tarpit atua como "Defesa em Profundidade", agindo onde a heurística de borda falha ao confundir scans furtivos e lentos com tráfego legítimo.

### C. O Dogma do "Fail Fast"
Desenvolvedores são treinados para rejeitar requisições inválidas no primeiro milissegundo. Reter a conexão ativa intencionalmente (segurando os descritores de arquivo na infraestrutura e a conexão TCP aberta) exige uma mudança de paradigma mental para abraçar o "Fail Slow" em caso de suspeita de abuso, o que assusta equipes que monitoram a métrica de *tempo de resposta médio*. 

## 3. A Implementação Segura no ErlangMS

O Barramento ErlangMS utiliza a Máquina Virtual de Erlang (BEAM), que não mapeia processos 1:1 para threads de SO. Em Erlang, suspender milhões de requests na instrução `timer:sleep/1` é extremamente barato em termos de CPU e RAM, pois não bloqueia as *Scheduler Threads* nativas da BEAM.

Ainda assim, o web server subjacente (Cowboy 1.x) aloca um conjunto predeterminado de *Workers* e limite máximo de conexões (`?HTTP_MAX_CONNECTIONS = 1024`). Logo, se o Tarpit atrasasse processos cegamente, uma enchente repentina esgotaria o Cowboy antes mesmo da BEAM se afogar, reproduzindo a paralisia detalhada no item 2.A.

### A Solução: Tarpit com Semáforo de Concorrência
Para resolver o problema do esgotamento de *workers*, o modelo contido em `ems_tarpit.erl` funciona protegido por um **semáforo de contagem atômico**, configurado na constante `?HTTP_TARPIT_MAX_BLOCKED` (ex: 25 threads).

O fluxo de processamento:
1. O servidor recebe um request de método de Injeção de Segurança, payload excessivo, método malicioso ou consulta em rota inexistente (404/Scanner Probe).
2. Tenta incrementar a trava atômica `ems_tarpit_active_counter`.
3. Se houver `N` threads ocupadas onde `N` é menor que o limite (`N <= 25`), a thread estaciona em um `timer:sleep(Delay)`.
4. Importante: Se e **apenas se** o semáforo já estiver ocupando o máximo de threads seguro, a defesa corta caminho e avança a negação sem o *sleep*. O request é negado imediatamente e removido do pool.

#### Benefício da Abordagem
Mesmo diante de um ataque na escala de milhares de *requests per second*, no máximo as 25 threads separadas intencionalmente para sacrifício segurarão as conexões adversárias no Limbo. Todo o restante recusa o impacto imediatamente. Ou seja: **A aplicação drena o adversário enquanto ainda protege a si mesma de um afogamento**.

**Proteção à Prova de Falhas:** O contador usa a estrutura de exceções da sintaxe do Erlang combinada para evitar vazamentos de capacidade. Até abortos do link TCP do usuário no meio do castigo (`sleep`) ativam a varredura atômica (`try...catch...after`) forçando a devolução do ticket de Semáforo Tarpit ao `atomics`. Nenhuma contagem é perdida, eliminando degradação silenciosa e bloqueio vitalício.

## 4. Referências e Literatura Recomendada

Para um estudo aprofundado sobre esses arquétipos clássicos e sobre o porquê resiliência significa gerenciar falhas de forma criativa:

1. **Nygard, M. (2018). *Release It!: Design and Deploy Production-Ready Software (2nd Ed.).*** Pragmatic Bookshelf.
   - *O manual definitivo sobre a realidade de software em produção. Leitura obrigatória para entender Padrões de Estabilidade (Stability Patterns), Fail Fast, Circuit Breakers, Bulkheads e a mecânica das falhas em cascata.*

2. **Johnsson, D. B. et al. (2019). *Secure by Design.*** Manning Publications.
   - *Explica a segurança como uma consequência do design em vez de adendos ou penduricalhos de código. Base para validar a ideia de que o design arquitetural bem pensado resolve classes inteiras de ataques (onde o Semáforo Lock-Free entra na camada Erlang).*

3. **Armstrong, J. (2007). *Programming Erlang: Software for a Concurrent World.*** Pragmatic Bookshelf.
   - *Escrito pelo criador do Erlang. Essencial para compreender a natureza leve dos processos BEAM (`timer:sleep` como uma operação quase grátis), a mecânica do `Let it crash` (Tratamento de Exceções) e o mapeamento N:M de schedulers.*
