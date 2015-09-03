%%********************************************************************
%% @title msbus_schema
%% @version 1.0.0
%% @doc Contém definições das estruturas de dados utilizadas.
%% @author Everton de Vargas Agilar <evertonagilar@gmail.com>
%% @copyright erlangMS Team
%%********************************************************************

-record(sequence, {key :: atom(), 
				   index :: non_neg_integer()}).

-record(user, {id :: non_neg_integer(), 
			   nome :: string(), 
			   email :: string(), 
			   senha :: string()}).
			   
-record(request, {
					  rid,       								%% Request ID (Identificador da requisição gerada automaticamente)
					  servico,   								%% Contrato que estabelece o serviço que vai atender a requisição
					  timestamp, 								%% Timestamp de quando que a requisição ocorreu
					  latencia :: non_neg_integer(),			%% Latência (tempo que levou para processar a requisição)
					  status,    								%% Código de retorno HTTP (Ex.: 202 OK, 404 Não Encontrado)
					  type :: string(),							%% Verbo HTTP (GET, POST, PUT, DELETE e OPTIONS)
					  url :: string(),							%% URL da requisição do serviço
					  versao_http :: string(),					%% Versão do cabeçalho HTTP
					  payload :: string(),						%% Corpo da requisição (aceita somente JSON)
					  payload_map :: map(),						%% Corpo da requisição convertida para map após o parser e validação
					  querystring :: string(),					%% Querystring da requisição
					  querystring_map,							%% Querystring convertida para map após o parser e validação
					  params_url,								%% Map com os parâmetros da URL
					  content_length :: non_neg_integer(), 		%% Largura da requisição
					  content_type :: string(),					%% Tipo de conteúdo (Ex.: application/json)
					  accept :: string(),						%% Parâmetro ACCEPT HTTP
					  user_agent :: string(),					%% Parâmetro USER_AGENT HTTP
					  accept_encoding :: string(),				%% Parâmetro ACCEPT_ENCODING HTTP
					  cache_control :: string(),				%% Parâmetro CACHE-CONTROL HTTP
					  host :: string(),							%% Host que iniciou a requisição
					  t1,										%% Utilizado para cálculo da latência (Tempo inicial em milisegundos)
					  socket :: gen_tcp:socket(),				%% Socket da requisição
					  worker :: pid()							%% Processo worker http que vai atender a requisição
				  }).

-record(servico, {
					rowid :: string(),  						%% Identificador interno do contrato (utilizado para localizar o contrato)
					id :: non_neg_integer(), 					%% Id sequencial gerado automaticamente e visível no portal API Management
					name :: string(), 							%% Nome do contrato do serviço (Por default usa-se a própria URL como nome)
					url :: string(),  							%% URL do contrato do serviço
					type :: string(),							%% Verbo HTTP do contrato (GET, POST, PUT, DELETE e OPTIONS)
					service :: string(),						%% Serviço que será executado no contrato
					module_name :: string(), 					%% Nome do módulo do serviço que vai atender a requisição. Ex.: br.erlangms.HelloWorldService  
					module_name_canonical :: string(), 			%% Nome do módulo canonico do serviço que vai atender a requisição. Ex.: HelloWorldService  
					module :: atom(),  							%% Atom do processo do módulo de serviço que vai atender a requisição
					function_name :: string(),					%% Nome da mensagem ou função que vai ser invocada no processo que vai atender a requisição
					function :: atom(),  						%% Atom da mensagem ou função que vai ser invocada no processo que vai atender a requisição
					id_re_compiled,   							%% Identificador da expressão regular que vai verificar se a URL bate com a URL da requisição
					apikey  :: boolean(), 						%% Indica se o contrato estará listado no Portal API Management
					comment :: string(), 						%% Comentário sobre o que o contrato oferece em termos de serviço
					version :: string(), 						%% Versão do contrato do serviço
					owner :: string(),  						%% Quem é o proprietário pelo serviço
					async :: boolean(), 						%% Indica se o serviço será processado em segundo plano (chamada assíncrona)
					querystring :: string(),  					%% Definição da querystring para o contrato do serviço
					qtd_querystring_req :: non_neg_integer(), 	%% Indica quantas querystrings são obrigatórias
					host :: atom(),  							%% Atom do host onde está o módulo do serviço que vai processar a requisição
					host_name :: string(),  					%% Nome do host onde está o módulo do serviço que vai processar a requisição
					result_cache :: non_neg_integer()  			%% Indica quanto tempo em milisegundos o resultado vai ficar armazenado em cache (somente para o módulo msbus_static_file_service)
				}).

