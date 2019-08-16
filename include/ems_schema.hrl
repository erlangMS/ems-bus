%%********************************************************************
%% @title ems_schema
%% @version 1.0.0
%% @doc It contains definitions of the data structures used.
%% @author Everton de Vargas Agilar <evertonagilar@gmail.com>
%% @copyright ErlangMS Team
%%********************************************************************

-record(encode_request_state, {http_max_content_length,
							   http_header_default,
							   http_header_options,
							   show_debug_response_headers,
							   current_node}).

-record(sequence, {key :: atom(), 
				   index :: non_neg_integer()}).

-record(counter, {key :: atom(), 
     			  value :: non_neg_integer()}).

-record(user, {id :: non_neg_integer(), 					%%  1 - id       				-> TB_Usuario.UsuId
			   codigo :: non_neg_integer(),					%%  2 - codigo   				-> Tb_Pessoa.PesCodigoPessoa
			   login :: binary(),							%%  3 - login	
			   name :: binary(), 							%%  4 - name		
			   cpf :: binary(),								%%  5 - cpf		
			   email :: binary(), 							%%  6 - email	
			   password :: binary(),						%%  7 - password 
			   dt_expire_password :: binary(),				%%  8 - dt_expire_password
			   type :: non_neg_integer(),					%%  9 - type       				-> 0 = interno  1 = tecnico  2 = docente  3 = discente, 4 = terceiros
			   subtype :: non_neg_integer(),				%% 10 - subtype 				-> se aluno códigos abaixo:
															%%			  		 			      1 = extensao 2 = graduacao 3 = aperfeicoamento 4 = especializacao 5 = mestrado 
															%%   					              6 = doutorado 7 = pos-doutorado 8 = residencia 9 = aluno especial - graduacao 
															%%           					     10 = aluno especial - pos-graduacao 11 = estagio em pos-graduacao
			   passwd_crypto :: binary(),					%% 11 - passwd_crypto 			-> Algoritmo criptografia: SHA1, MD5
			   type_email :: non_neg_integer(),				%% 12 - type_email				-> undefined = desconhecido  1 = Institucional  2 = Pessoal
			   active :: boolean(),							%% 13 - active
			   endereco :: binary(),						%% 14 - endereco
			   complemento_endereco :: binary(),			%% 15 - complemento_endereco
			   bairro :: binary(),							%% 16 - bairro
			   cidade :: binary(),							%% 17 - cidade
			   uf :: binary(),								%% 18 - uf
			   cep :: binary(),								%% 19 - cep
			   rg :: binary(),								%% 20 - rg	
			   data_nascimento :: binary(),					%% 21 - data_nascimento
			   sexo :: non_neg_integer(),					%% 22 - sexo
			   telefone :: binary(),						%% 23 - telefone
			   celular :: binary(),							%% 24 - celular
			   ddd :: binary(),								%% 25 - ddd
			   nome_pai :: binary(),						%% 26 - nome_pai
			   nome_mae :: binary(),						%% 27 - nome_ae
			   nacionalidade :: non_neg_integer(),			%% 28 - nacionalidade
			   remap_user_id :: non_neg_integer(),			%% 29 - remap_user_id
			   admin = false :: boolean(),					%% 30 - admin					-> alguns web services podem ser acedidos somente por admins
			   old_login :: binary(),						%% 31 - old_login	
			   old_name :: binary(), 						%% 32 - old_name		
			   old_cpf :: binary(),							%% 33 - old_cpf		
			   old_email :: binary(), 						%% 34 - old_email	
			   old_password :: binary(),					%% 35 - old_password 
			   ctrl_path :: string(),						%% 36 - ctrl_path
			   ctrl_file :: string(),						%% 37 - ctrl_file
			   ctrl_insert :: binary(),						%% 38 - ctrl_insert				-> Data que foi inserido no banco mnesia
			   ctrl_update :: binary(), 					%% 39 - ctrl_update				-> Data que foi atualiado no banco mnesia			
			   ctrl_modified :: binary(),					%% 40 - ctrl_modified			-> Data que foi modificado na fonte onde está cadastrado (em disco ou banco de dados externo)
			   ctrl_hash :: non_neg_integer(),				%% 41 - ctrl_hash 				-> Hash gerado para poder comparar dois registros	
			   ctrl_last_login :: binary(),					%% 42 - ctrl_last_login			-> Atualizado toda vez que ems_user:find_index_by_login_and_password é executado
			   ctrl_login_count = 0 :: non_neg_integer(),	%% 43 - ctrl_login_count		-> Incrementado toda vez que ems_user:find_index_by_login_and_password é executado
			   ctrl_last_login_scope :: atom(),				%% 44 - ctrl_last_login_scope	-> Qual tabela que encontrou o usuário
			   ctrl_last_login_client :: binary(),			%% 45 - ctrl_last_login_client	-> Em qual cliente logou
			   ctrl_source_type :: atom()					%% 46 - ctrl_source_type		-> nome da tabela onde os dados são armazenados
		}).
		
-define(USER_SCHEMA_DESCRIPTOR, {
			   atom_type,									%%  0 - nome da tabela	
			   non_neg_integer_type, 						%%  1 - id   
			   non_neg_integer_type,						%%  2 - codigo
			   binary_type,									%%  3 - login	
			   binary_type, 								%%  4 - name		
			   binary_type,									%%  5 - cpf		
			   binary_type, 								%%  6 - email	
			   binary_type,									%%  7 - password 
			   binary_type,									%%  8 - dt_expire_password
			   non_neg_integer_type,						%%  9 - type
			   non_neg_integer_type,						%% 10 - subtype
			   binary_type,									%% 11 - passwd_crypto
			   non_neg_integer_type,						%% 12 - type_email
			   boolean_type,								%% 13 - active
			   binary_type,									%% 14 - endereco
			   binary_type,									%% 15 - complemento_endereco
			   binary_type,									%% 16 - bairro
			   binary_type,									%% 17 - cidade
			   binary_type,									%% 18 - uf
			   binary_type,									%% 19 - cep
			   binary_type,									%% 20 - rg	
			   binary_type,									%% 21 - data_nascimento
			   non_neg_integer_type,						%% 22 - sexo
			   binary_type,									%% 23 - telefone
			   binary_type,									%% 24 - celular
			   binary_type,									%% 25 - ddd
			   binary_type,									%% 26 - nome_pai
			   binary_type,									%% 27 - nome_ae
			   non_neg_integer_type,						%% 28 - nacionalidade
			   non_neg_integer_type,						%% 29 - remap_user_id
			   boolean_type,								%% 30 - admin	
			   binary_type,									%% 31 - old_login	
			   binary_type, 								%% 32 - old_name		
			   binary_type,									%% 33 - old_cpf		
			   binary_type, 								%% 34 - old_email	
			   binary_type,									%% 35 - old_password 
			   string_type,									%% 36 - ctrl_path
			   string_type,									%% 37 - ctrl_file
			   binary_type,									%% 38 - ctrl_insert
			   binary_type, 								%% 39 - ctrl_update
			   binary_type,									%% 40 - ctrl_modified
			   non_neg_integer_type,						%% 41 - ctrl_hash 	
			   binary_type,									%% 42 - ctrl_last_login
			   non_neg_integer_type, 						%% 43 - ctrl_login_count
			   atom_type,									%% 44 - ctrl_last_login_scope
			   binary_type,									%% 45 - ctrl_last_login_client
			   atom_type									%% 46 - ctrl_source_type
			}).		
		
%
% Muitos atributos são armazenados no histórico pois as tabelas origem podem mudar
%
-record(user_history, {
			   id :: non_neg_integer(), 						%%  1 - id
			   user_id :: non_neg_integer(), 					%%  2 - user_id
			   user_codigo :: non_neg_integer(),				%%  3 - user_codigo
			   user_login :: binary(),							%%  4 - user_login
			   user_name :: binary(), 							%%  5 - user_name
			   user_cpf :: binary(),							%%  6 - user_cpf
			   user_email :: binary(), 							%%  7 - user_email
			   user_type :: non_neg_integer(),					%%  8 - user_type
			   user_subtype :: non_neg_integer(),				%%  9 - user_subtype
			   user_type_email :: non_neg_integer(),			%% 10 - user_type_email
			   user_active :: boolean(),						%% 11 - user_active
			   user_admin :: boolean(),							%% 12 - user_admin
			   client_id :: non_neg_integer(), 					%% 13 - client_id
			   client_name :: binary(), 						%% 14 - client_name
			   service_rowid :: non_neg_integer(), 				%% 15 - service_rowid
			   service_name :: binary(), 						%% 16 - service_name
			   service_url :: string(),  						%% 17 - service_url
			   service_type :: binary(),						%% 18 - service_type
			   service_service :: binary(),						%% 19 - service_service
			   service_use_re :: boolean(),						%% 20 - service_use_re
			   service_public :: boolean(), 					%% 21 - service_public
			   service_version :: binary(), 					%% 22 - service_version
			   service_owner :: binary(),  						%% 23 - service_owner
			   service_group :: binary(),  						%% 24 - service_group
			   owner :: binary(),  								%% 25 - owner
			   service_async :: boolean(),						%% 26 - service_async
			   request_rid :: non_neg_integer(),  				%% 27 - request_rid
			   request_type :: binary(),						%% 28 - request_type
			   request_uri :: binary(),							%% 29 - request_uri
			   request_url :: binary(),							%% 30 - request_url
			   request_url_masked :: boolean(),					%% 31 - request_url_masked
			   request_http_version :: binary(),				%% 32 - request_http_version
			   request_querystring :: binary(),					%% 33 - request_querystring
			   request_content_type_in :: binary(),				%% 34 - request_content_type_in
			   request_content_type_out :: binary(),			%% 35 - request_content_type_out
			   request_content_length :: non_neg_integer(), 	%% 36 - request_content_length
			   request_accept :: binary(),						%% 37 - request_accept
			   request_user_agent :: binary(),					%% 38 - request_user_agent
			   request_user_agent_version :: binary(),			%% 39 - request_user_agent_version
			   request_t1 :: non_neg_integer(),					%% 40 - request_t1
			   request_authorization :: binary(),				%% 41 - request_authorization
			   request_port :: non_neg_integer(),				%% 42 - request_port
			   request_bash :: non_neg_integer(),				%% 43 - request_bash
			   request_host :: binary(),						%% 44 - request_host
			   request_filename :: string(),					%% 45 - request_filename
			   request_referer :: binary(),						%% 46 - request_referer
			   request_access_token :: binary(),				%% 47 - request_access_token
			   request_operation :: atom(),						%% 48 - request_operation
			   request_reason_detail :: atom(),					%% 49 - request_reason_detail
			   request_reason :: atom(),						%% 50 - request_reason
			   request_code :: non_neg_integer(),	 			%% 51 - request_code
			   request_protocol :: atom(),						%% 52 - request_protocol
   			   request_date :: binary(),						%% 53 - request_date
   			   request_time :: binary(),						%% 54 - request_time
   			   request_payload :: binary(),						%% 55 - request_payload
   			   request_params_url :: binary()					%% 56 - request_params_url
		}).


-define(USER_HISTORY_DESCRIPTOR, {
			   atom_type,										%%  0 - nome da tabela	
			   non_neg_integer_type, 							%%  1 - id   
			   non_neg_integer_type, 							%%  2 - user_id   
			   non_neg_integer_type,							%%  3 - user_codigo
			   binary_type,										%%  4 - user_login	
			   binary_type,										%%  5 - user_name	
			   binary_type,										%%  6 - user_cpf
			   binary_type,										%%  7 - user_email
			   non_neg_integer_type,							%%  8 - user_type
			   non_neg_integer_type,							%%  9 - user_subtype
			   non_neg_integer_type,							%% 10 - user_type_email
			   boolean_type,									%% 11 - user_active
			   boolean_type,									%% 12 - user_admin
			   non_neg_integer_type,							%% 13 - client_id
			   binary_type,										%% 14 - client_name
			   non_neg_integer_type,							%% 15 - service_rowid
			   binary_type,										%% 16 - service_name
			   string_type,										%% 17 - service_url
			   binary_type,										%% 18 - service_type
			   binary_type,										%% 19 - service_service
			   boolean_type,									%% 20 - service_use_re
			   boolean_type,									%% 21 - service_public
			   binary_type,										%% 22 - service_version
			   binary_type,										%% 23 - service_owner
			   binary_type,										%% 24 - service_group
			   binary_type,										%% 25 - owner
			   boolean_type,									%% 26 - service_async
			   non_neg_integer_type,							%% 27 - request_rid
			   binary_type,										%% 28 - request_type
			   binary_type,										%% 29 - request_uri
			   binary_type,										%% 30 - request_url
			   boolean_type,									%% 31 - request_url_masked
			   binary_type,										%% 32 - request_http_version
			   binary_type,										%% 33 - request_querystring
			   binary_type,										%% 34 - request_content_type_in
			   binary_type,										%% 35 - request_content_type_out
			   non_neg_integer_type,							%% 36 - request_content_length
			   binary_type,										%% 37 - request_accept
			   binary_type,										%% 38 - request_user_agent
			   binary_type,										%% 39 - request_user_agent_version
			   non_neg_integer_type,							%% 40 - request_t1
			   binary_type,										%% 41 - request_authorization
			   non_neg_integer_type,							%% 42 - request_port
			   non_neg_integer_type,							%% 43 - request_bash
			   binary_type,										%% 44 - request_host
			   string_type,										%% 45 - request_filename
			   binary_type,										%% 46 - request_referer
			   binary_type,										%% 47 - request_access_token
			   atom_type,										%% 48 - request_operation
			   atom_type,										%% 49 - request_reason_detail
			   atom_type,										%% 50 - request_reason
			   non_neg_integer_type,							%% 51 - request_code
			   atom_type,										%% 52 - request_protocol
			   binary_type,										%% 53 - request_date
			   binary_type,										%% 54 - request_time
			   binary_type,										%% 55 - request_payload
			   binary_type										%% 56 - request_params_url
			}).		

		
-record(user_dados_funcionais, {
			   id :: non_neg_integer(), 					%%  1 - matricula
			   type :: non_neg_integer(),					%%  2 - type     interno  1 = tecnico  2 = docente  3 = discente
			   subtype :: non_neg_integer(),				%%  3 - subtype  se aluno,  1 = extensao 2 = graduacao 3 = aperfeicoamento 4 = especializacao 5 = mestrado 6 = doutorado 7 = pos-doutorado 8 = residencia 9 = aluno especial - graduacao 10 = aluno especial - pos-graduacao 11 = estagio em pos-graduacao
			   active :: boolean(),							%%  4 - active
			   user_id :: non_neg_integer(),				%%  5 - id do usuário
			   ctrl_path :: string(),						%% 14 - ctrl_path
			   ctrl_file :: string(),						%% 15 - ctrl_file
			   ctrl_insert :: binary(),						%% 16 - ctrl_insert				-> Data que foi inserido no banco mnesia
			   ctrl_update :: binary(), 					%% 17 - ctrl_update				-> Data que foi atualiado no banco mnesia			
			   ctrl_modified :: binary(),					%% 18 - ctrl_modified			-> Data que foi modificado na fonte onde está cadastrado (em disco ou banco de dados externo)
			   ctrl_hash :: non_neg_integer()				%% 19 - ctrl_hash 				-> Hash gerado para poder comparar dois registros	
		}).
		
-define(USER_DADOS_FUNCIONAIS_SCHEMA_DESCRIPTOR, {
			   atom_type,									%%  1 - matricula
			   non_neg_integer_type, 						%%  1 - id   
			   non_neg_integer_type,						%%  2 - type
			   non_neg_integer_type,						%%  3 - subtype
			   boolean_type,								%%  4 - active
			   non_neg_integer_type,						%%  5 - id do usuário
			   string_type,									%%  6 - ctrl_path
			   string_type,									%%  7 - ctrl_file
			   binary_type,									%%  8 - ctrl_insert
			   binary_type, 								%%  9 - ctrl_update
			   binary_type,									%% 10 - ctrl_modified
			   non_neg_integer_type							%% 11 - ctrl_hash 	
		}).
		

-record(user_email, {
			   id :: non_neg_integer(), 					%%  1 - id
			   codigo :: non_neg_integer(),					%%  2 - codigo
			   email :: binary(),							%%  3 - email
			   type :: non_neg_integer(),					%%  4 - type         1 = institucional  2 = outro
			   ctrl_path :: string(),						%%  5 - ctrl_path
			   ctrl_file :: string(),						%%  6 - ctrl_file
			   ctrl_insert :: binary(),						%%  7 - ctrl_insert				-> Data que foi inserido no banco mnesia
			   ctrl_update :: binary(), 					%%  8 - ctrl_update				-> Data que foi atualiado no banco mnesia			
			   ctrl_modified :: binary(),					%%  9 - ctrl_modified			-> Data que foi modificado na fonte onde está cadastrado (em disco ou banco de dados externo)
			   ctrl_hash :: non_neg_integer()				%% 10 - ctrl_hash 				-> Hash gerado para poder comparar dois registros	
		}).

-define(USER_EMAIL_SCHEMA_DESCRIPTOR, {
			   atom_type,									%%  0 - nome da tabela	
			   non_neg_integer_type, 						%%  1 - id   
			   non_neg_integer_type,						%%  2 - codigo
			   binary_type,									%%  3 - email
			   non_neg_integer_type,						%%  4 - type
			   string_type,									%%  5 - ctrl_path
			   string_type,									%%  6 - ctrl_file
			   binary_type,									%%  7 - ctrl_insert
			   binary_type, 								%%  8 - ctrl_update
			   binary_type,									%%  9 - ctrl_modified
			   non_neg_integer_type							%% 10 - ctrl_hash 	
		}).

-record(user_endereco, {
			   id :: non_neg_integer(), 					%%  1 - id
			   codigo :: non_neg_integer(),					%%  2 - código
			   endereco :: binary(),						%%  3 - endereco
			   complemento :: binary(),						%%  4 - complemento
			   bairro :: binary(),							%%  5 - bairro
			   cidade :: binary(),							%%  6 - cidade
			   uf :: binary(),								%%  7 - uf
			   cep :: binary(),								%%  8 - cep
			   type :: non_neg_integer(),					%%  9 - type        1 = residencial  2 = comercial 3 = exterior 4 = outro
			   ctrl_path :: string(),						%% 10 - ctrl_path
			   ctrl_file :: string(),						%% 11 - ctrl_file
			   ctrl_insert :: binary(),						%% 12 - ctrl_insert				-> Data que foi inserido no banco mnesia
			   ctrl_update :: binary(), 					%% 13 - ctrl_update				-> Data que foi atualiado no banco mnesia			
			   ctrl_modified :: binary(),					%% 14 - ctrl_modified			-> Data que foi modificado na fonte onde está cadastrado (em disco ou banco de dados externo)
			   ctrl_hash :: non_neg_integer()				%% 15 - ctrl_hash 				-> Hash gerado para poder comparar dois registros	
		}).

-define(USER_ENDERECO_SCHEMA_DESCRIPTOR, {
			   atom_type,									%%  0 - nome da tabela	
			   non_neg_integer_type, 						%%  1 - id   
			   non_neg_integer_type,						%%  2 - codigo
			   binary_type,									%%  3 - email
			   non_neg_integer_type,						%%  4 - type
			   string_type,									%%  5 - ctrl_path
			   string_type,									%%  6 - ctrl_file
			   binary_type,									%%  7 - ctrl_insert
			   binary_type, 								%%  8 - ctrl_update
			   binary_type,									%%  9 - ctrl_modified
			   non_neg_integer_type							%% 10 - ctrl_hash 	
		}).



-record(user_telefone, {
			   id :: non_neg_integer(), 					%%  1 - id
			   codigo :: non_neg_integer(),					%%  2 - codigo
			   numero :: binary(),							%%  3 - numero
			   ramal :: non_neg_integer(),					%%  4 - ramal
			   ddd :: binary(),								%%  5 - ddd
			   type :: non_neg_integer(),					%%  6 - type 		1 = celular  2 = comercial 3 = residencial
			   ctrl_path :: string(),						%%  7 - ctrl_path
			   ctrl_file :: string(),						%%  8 - ctrl_file
			   ctrl_insert :: binary(),						%%  9 - ctrl_insert				-> Data que foi inserido no banco mnesia
			   ctrl_update :: binary(), 					%% 10 - ctrl_update				-> Data que foi atualiado no banco mnesia			
			   ctrl_modified :: binary(),					%% 11 - ctrl_modified			-> Data que foi modificado na fonte onde está cadastrado (em disco ou banco de dados externo)
			   ctrl_hash :: non_neg_integer()				%% 12 - ctrl_hash 				-> Hash gerado para poder comparar dois registros	
		}).

-define(USER_TELEFONE_SCHEMA_DESCRIPTOR, {
			   atom_type,									%%  0 - nome da tabela	
			   non_neg_integer_type, 						%%  1 - id   
			   non_neg_integer_type,						%%  2 - codigo
			   binary_type,									%%  3 - numero
			   non_neg_integer_type,						%%  4 - ramal
			   binary_type,									%%  5 - ddd
			   non_neg_integer_type,						%%  6 - type
			   string_type,									%%  7 - ctrl_path
			   string_type,									%%  8 - ctrl_file
			   binary_type,									%%  9 - ctrl_insert
			   binary_type, 								%% 10 - ctrl_update
			   binary_type,									%% 11 - ctrl_modified
			   non_neg_integer_type							%% 12 - ctrl_hash 	
		}).



-record(user_permission, {id :: non_neg_integer(),				%%  1 - id
						  user_id :: non_neg_integer(),			%%  2 - user_id
						  client_id :: non_neg_integer(),		%%  3 - client_id
						  perfil_id :: non_neg_integer(),		%%  4 - perfil_id
						  hash :: non_neg_integer(),			%%  5 - hash
						  hash2 :: non_neg_integer(),			%%  6 - hash2
						  name :: binary(),						%%  7 - name
						  url :: binary(),						%%  8 - url
						  grant_get :: boolean(),				%%  9 - grant_get
						  grant_post :: boolean(),				%% 10 - grant_post
						  grant_put :: boolean(),				%% 11 - grant_put
						  grant_delete :: boolean(),			%% 12 - grant_delete
						  position :: non_neg_integer(),		%% 13 - position
						  ctrl_path :: string(),				%% 14 - ctrl_path
						  ctrl_file :: string(),				%% 15 - ctrl_file
						  ctrl_insert :: binary(),				%% 16 - ctrl_insert				-> Data que foi inserido no banco mnesia
						  ctrl_update :: binary(), 				%% 17 - ctrl_update				-> Data que foi atualiado no banco mnesia			
						  ctrl_modified :: binary(),			%% 18 - ctrl_modified			-> Data que foi modificado na fonte onde está cadastrado (em disco ou banco de dados externo)
						  ctrl_hash :: non_neg_integer(),		%% 19 - ctrl_hash 				-> Hash gerado para poder comparar dois registros
						  glyphicon :: binary()				    %% 20 - glyphicon	
          }).


-define(USER_PERMISSION_SCHEMA_DESCRIPTOR, {
			   atom_type,										%%  0 - nome da tabela	
			   non_neg_integer_type, 							%%  1 - id   
			   non_neg_integer_type,							%%  2 - user_id
			   non_neg_integer_type,							%%  3 - client_id
			   non_neg_integer_type,							%%  4 - perfil_id
			   non_neg_integer_type,							%%  5 - bash
			   non_neg_integer_type,							%%  6 - bash2
			   binary_type,										%%  7 - name
			   binary_type,										%%  8 - url
			   boolean_type,									%%  9 - grant_get
			   boolean_type,									%% 10 - grant_post
			   boolean_type,									%% 11 - grant_put
			   boolean_type,									%% 12 - grant_delete
			   non_neg_integer_type,							%% 13 - position
			   string_type,										%% 14 - ctrl_path
			   string_type,										%% 15 - ctrl_file
			   binary_type,										%% 16 - ctrl_insert
			   binary_type, 									%% 17 - ctrl_update
			   binary_type,										%% 18 - ctrl_modified
			   non_neg_integer_type,							%% 19 - ctrl_hash 	
			   binary_type										%% 20 - glyphicon
		}).


-record(user_perfil, {id :: non_neg_integer(), 				%%  1 - id
					  perfil_id :: non_neg_integer(), 		%%  2 - perfil_id				
					  user_id :: non_neg_integer(),			%%  3 - user_id			
					  client_id :: non_neg_integer(),		%%  4 - client_id		
					  name :: binary(), 					%%  5 - name
					  ctrl_path :: string(),				%%  6 - ctrl_path
					  ctrl_file :: string(),				%%  7 - ctrl_file
					  ctrl_insert :: binary(),				%%  8 - ctrl_insert				-> Data que foi inserido no banco mnesia
					  ctrl_update :: binary(), 				%%  9 - ctrl_update				-> Data que foi atualiado no banco mnesia			
					  ctrl_modified :: binary(),			%% 10 - ctrl_modified			-> Data que foi modificado na fonte onde está cadastrado (em disco ou banco de dados externo)
					  ctrl_hash :: non_neg_integer()		%% 11 - ctrl_hash 				-> Hash gerado para poder comparar dois registros	
		}).
          
-define(USER_PERFIL_SCHEMA_DESCRIPTOR, {
			   atom_type,									%%  0 - nome da tabela	
			   non_neg_integer_type, 						%%  1 - id  
			   non_neg_integer_type,           				%%  1 - perfil_id
			   non_neg_integer_type,						%%  2 - user_id
			   non_neg_integer_type,						%%  3 - client_id
			   binary_type,									%%  4 - name
			   string_type,									%%  5 - ctrl_path
			   string_type,									%%  6 - ctrl_file
			   binary_type,									%%  7 - ctrl_insert
			   binary_type, 								%%  8 - ctrl_update
			   binary_type,									%%  9 - ctrl_modified
			   non_neg_integer_type							%% 10 - ctrl_hash 	
		}).


-record(client, {id :: non_neg_integer(), 					%%  1 - id       				
				 name :: binary(), 							%%  2 - name
			     description :: binary(),					%%  3 - description
			     secret :: binary(),						%%  4 - secret
				 redirect_uri :: binary(),					%%  5 - redirect_uri
				 active :: boolean(),						%%  6 - active
				 scope :: binary(),							%%  7 - scope	
				 version :: binary(),						%%  8 - version
				 group :: binary(), 						%%  9 - group
				 glyphicon :: binary(),						%% 10 - glyphicon
			     rest_base_url :: binary(),				    %% 11 - rest_base_url
			     rest_auth_url :: binary(),					%% 12 - rest_auth_url
			     ctrl_path :: string(),						%% 13 - ctrl_path
			     ctrl_file :: string(),						%% 14 - ctrl_file
			     ctrl_insert :: binary(),					%% 15 - ctrl_insert				-> Data que foi inserido no banco mnesia
			     ctrl_update :: binary(), 					%% 16 - ctrl_update				-> Data que foi atualiado no banco mnesia			
			     ctrl_modified :: binary(),					%% 17 - ctrl_modified			-> Data que foi modificado na fonte onde está cadastrado (em disco ou banco de dados externo)
			     ctrl_hash :: non_neg_integer()				%% 18 - ctrl_hash 				-> Hash gerado para poder comparar dois registros	
		}).


-define(CLIENT_SCHEMA_DESCRIPTOR, {
			   atom_type,									%%  0 - nome da tabela	
			   non_neg_integer_type, 						%%  1 - id   
			   binary_type,									%%  2 - name
			   binary_type,									%%  3 - description
			   binary_type,									%%  4 - secret
			   binary_type,									%%  5 - redirect_uri
			   boolean_type,								%%  6 - active
			   binary_type,									%%  7 - scope
			   binary_type,									%%  8 - version
			   binary_type,									%%  9 - group
			   binary_type,									%% 10 - glyphicon
			   binary_type,									%% 11 - rest_base_url
			   binary_type,									%% 12 - rest_auth_url
			   string_type,									%% 13 - ctrl_path
			   string_type,									%% 14 - ctrl_file
			   binary_type,									%% 15 - ctrl_insert
			   binary_type, 								%% 16 - ctrl_update
			   binary_type,									%% 17 - ctrl_modified
			   non_neg_integer_type							%% 18 - ctrl_hash 	
		}).

-record(ctrl_params, {name :: string(),
					  value
		}).



-record(service_datasource, {id :: non_neg_integer(),									%%  1 - id
							 rowid :: non_neg_integer(),								%%  2 - rowid
							 type :: atom(),											%%  3 - type					-> postgresql, sqlserver, csvfile, mnesia
							 driver :: atom(),											%%  4 - driver					-> sqlite3, odbc, undefined
							 connection :: string(),									%%  5 - connection		
							 table_name :: binary() | atom() | list(atom()),			%%  6 - table_name
							 fields :: binary() | atom() | list(atom()),				%%  7 - fields
							 remap_fields :: map(),										%%  8 - remap_fields			-> Permite expor um campo com outro nome
							 remap_fields_rev :: map(),									%%  9 - remap_fields_rev
							 show_remap_fields :: boolean(),							%% 10 - show_remap_fields		-> Indica se deve mostrar os campos remapeados
							 primary_key :: binary() | atom(),							%% 11 - primary_key
							 foreign_key :: binary() | atom(),							%% 12 - foreign_key
							 foreign_table_name  :: binary() | atom(),					%% 13 - foreign_table_name
							 csv_delimiter :: binary(),									%% 14 - csv_delimiter
							 sql :: binary(),											%% 15 - sql
							 timeout :: non_neg_integer(),								%% 16 - timeout
							 max_pool_size :: non_neg_integer(),						%% 17 - max_pool_size
							 conn_ref,													%% 18 - conn_ref
							 pid_module,												%% 19 - pid_module
							 pid_module_ref,											%% 20 - pid_module_ref
							 owner,														%% 21 - owner
							 owner_ref,													%% 22 - owner_ref
							 connection_count_metric_name :: atom(),					%% 23 - connection_count_metric_name
							 connection_created_metric_name :: atom(),					%% 24 - connection_created_metric_name
							 connection_closed_metric_name :: atom(),   				%% 25 - connection_closed_metric_name
							 connection_shutdown_metric_name :: atom(), 				%% 26 - connection_shutdown_metric_name
							 connection_reuse_metric_name :: atom(), 					%% 27 - connection_reuse_metric_name
							 connection_unavailable_metric_name :: atom(), 				%% 28 - connection_unavailable_metric_name
							 connection_max_pool_size_exceeded_metric_name :: atom(), 	%% 29 - connection_max_pool_size_exceeded_metric_name
							 sql_check_valid_connection :: string(),					%% 30 - sql_check_valid_connection
							 check_valid_connection_timeout :: non_neg_integer(),		%% 31 - check_valid_connection_timeout
							 close_idle_connection_timeout :: non_neg_integer(),		%% 32 - close_idle_connection_timeout
							 log_show_odbc_pool_activity = true :: boolean(),			%% 33 - log_show_odbc_pool_activity
							 ctrl_path :: string(),										%% 34 - ctrl_path
							 ctrl_file :: string(),										%% 35 - ctrl_file
							 ctrl_insert :: binary(),									%% 36 - ctrl_insert				-> Data que foi inserido no banco mnesia
							 ctrl_update :: binary(), 									%% 37 - ctrl_update				-> Data que foi atualiado no banco mnesia			
							 ctrl_modified :: binary(),									%% 38 - ctrl_modified			-> Data que foi modificado na fonte onde está cadastrado (em disco ou banco de dados externo)
							 ctrl_hash :: non_neg_integer(),							%% 39 - ctrl_hash 				-> Hash gerado para poder comparar dois registros	
							 ds_name :: binary()
							}).

-define(SERVICE_DATASOURCE_DESCRIPTOR, {
			   atom_type,									%%  0 - nome da tabela	
			   non_neg_integer_type, 						%%  1 - id   
			   non_neg_integer_type,						%%  2 - rowid
			   atom_type,									%%  3 - type
			   atom_type,									%%  4 - driver
			   string_type,									%%  5 - connection		
			   undefined,									%%  6 - table_name
			   undefined, 									%%  7 - fields
			   undefined, 									%%  8 - remap_fields
			   undefined,									%%  9 - remap_fields_rev
			   boolean_type, 								%% 10 - show_remap_fields
			   undefined,									%% 11 - primary_key
			   undefined, 									%% 12 - foreign_key
			   undefined,									%% 13 - foreign_table_name
			   binary_type,									%% 14 - csv_delimiter
			   binary_type, 								%% 15 - sql
			   non_neg_integer_type,						%% 16 - timeout
			   non_neg_integer_type, 						%% 17 - max_pool_size
			   undefined,									%% 18 - conn_ref
			   undefined,									%% 19 - pid_module
			   undefined, 									%% 20 - pid_module_ref
			   undefined,									%% 21 - owner
			   undefined, 									%% 22 - owner_ref
			   atom_type, 									%% 23 - connection_count_metric_name
			   atom_type, 									%% 24 - connection_created_metric_name
			   atom_type, 					  				%% 25 - connection_closed_metric_name
			   atom_type, 									%% 26 - connection_shutdown_metric_name
			   atom_type, 				 					%% 27 - connection_reuse_metric_name
			   atom_type, 									%% 28 - connection_unavailable_metric_name
			   atom_type, 								 	%% 29 - connection_max_pool_size_exceeded_metric_name
			   boolean_type,								%% 30 - sql_check_valid_connection
			   non_neg_integer_type, 						%% 31 - check_valid_connection_timeout
			   non_neg_integer_type, 						%% 32 - close_idle_connection_timeout
			   boolean_type, 								%% 33 - log_show_odbc_pool_activity
			   string_type,									%% 34 - ctrl_path
			   string_type, 								%% 35 - ctrl_file
			   binary_type, 								%% 36 - ctrl_insert
			   binary_type, 								%% 37 - ctrl_update
			   binary_type,									%% 38 - ctrl_modified
			   non_neg_integer_type,						%% 39 - ctrl_hash
			   binary_type 									%% 40 - ds_name
		}).



-record(service_owner, {  id :: non_neg_integer(),
						   name :: string(),
						   title :: string(),
						   comment :: string()
						}).


-record(service, {  id :: non_neg_integer(), 								%%  1 - id
					rowid :: non_neg_integer(),								%%  2 - rowid									-> Identificador interno gerado para o contrato (utilizado para localizar o contrato)
					name :: binary(), 										%%  3 - name									-> Nome do contrato do serviço (Por default usa-se a própria URL como name)
					url :: binary(),  										%%  4 - url										-> URL do contrato do serviço
					type :: binary(),										%%  5 - type									-> Verbo HTTP do contrato (GET, POST, PUT, DELETE e OPTIONS) ou KERNEL para módulos do barramento
					service :: binary(),									%%  6 - service									-> Serviço que será executado no contrato
					middleware :: atom(),									%%  7 - middleware								-> Middleware para execução após processamento do serviço
					module_name :: string(), 								%%  8 - module_name								-> Nome do módulo do serviço que vai atender a requisição. Ex.: br.erlangms.HelloWorldService  
					module_name_canonical :: string(), 						%%  9 - module_name_canonical					-> Nome do módulo canonico do serviço que vai atender a requisição. Ex.: HelloWorldService  
					module :: atom(),  										%% 10 - module 									-> Atom do processo do módulo de serviço que vai atender a requisição
					function_name :: string(),								%% 11 - function_name							-> Nome da mensagem ou função que vai ser invocado para atender a requisição
					function :: atom(),  									%% 12 - function 								-> Atom da mensagem ou função que vai ser invocado para atender a requisição
					use_re = false :: boolean(),							%% 13 - use_re									-> Flag que indica se usa expressão regular
					id_re_compiled = undefined, 							%% 14 - id_re_compiled							-> Expressão regular compilada
					public = true :: boolean(), 							%% 15 - public									-> Indica se o contrato estará listado no Portal API Management
					comment :: binary(), 									%% 16 - comment									-> Comentário sobre o que o contrato oferece em termos de serviço
					version :: binary(), 									%% 17 - version									-> Versão do contrato do serviço
					owner :: binary(),  									%% 18 - owner									-> Quem é o proprietário pelo serviço. Ex.: auth
					group :: binary(),										%% 19 - group									-> Quem é o grupo do serviço. Ex.: auth/user
					async = false :: boolean(),										%% 20 - async									-> Indica se o serviço será processado em segundo plano (chamada assíncrona)
					querystring :: list(map()),								%% 21 - querystring								-> Definição da querystring para o contrato do serviço
					qtd_querystring_req :: non_neg_integer(), 				%% 22 - qtd_querystring_req						-> Indica quantas querystrings são obrigatórias
					host :: atom(),  										%% 23 - host									-> Atom do host onde está o módulo do serviço que vai processar a requisição
					host_name :: binary(),	  								%% 24 - host_name								-> Nome do host onde está o módulo do serviço que vai processar a requisição
					result_cache :: non_neg_integer(), 						%% 25 - result_cache							-> Indica quanto tempo em milisegundos o resultado vai ficar armazenado em cache
					authorization :: atom(),								%% 26 - authorization							-> Forma de autenticação (public, basic, oauth2)
					authorization_public_check_credential :: boolean(),		%% 27 - authorization_public_check_credential	-> Faz a checagem da credencial do usuário quando o serviço é publico
					oauth2_with_check_constraint :: boolean(),				%% 28 - oauth2_with_check_constraint	
					oauth2_allow_client_credentials :: boolean(),			%% 29 - oauth2_allow_client_credentials
					oauth2_token_encrypt :: boolean(),						%% 30 - oauth2_token_encrypt
					auth_allow_user_inative_credentials :: boolean(),  		%% 31 - auth_allow_user_inative_credentials 	-> Permite login de usuários inativos.
					page :: binary(),										%% 32 - page									-> Page django file
					page_module :: pid(),									%% 33 - page_module								-> Page module django file compiled
					page_mime_type :: binary(),								%% 34 - page_mime_type							-> Page mime type
					node :: list(),											%% 35 - node									-> Node ou lista de node onde os serviços estão publicados
					lang :: binary(),										%% 36 - lang									-> Linguagem que foi utilizada para implementar o serviço
					datasource :: #service_datasource{},					%% 37 - datasource								-> Datasource para a fonte de dados
					debug = false :: boolean(),								%% 38 - debug									-> Permite habilitar um modo debug (depende da implementação do serviço)
					schema_in :: non_neg_integer(),							%% 39 - schema_in
					schema_out :: non_neg_integer(),						%% 40 - schema_out
					pool_size :: non_neg_integer(),							%% 41 - pool_size
					pool_max :: non_neg_integer(),							%% 42 - pool_max
					timeout :: non_neg_integer(),							%% 43 - timeout									-> Tempo que o dispatcher aguarda em milisegundos o processamento de um serviço antes de retornar etimeout_service para o cliente
					timeout_alert_threshold :: non_neg_integer(),  			%% 44 - timeout_alert_threshold					-> Emite um alert no log após aguardar um determinado serviço por x milisegundos. O valor 0 (zero) desliga o threshold.
					log_show_response = false :: boolean(),					%% 45 - log_show_response						-> Se true, imprime o response no log
					log_show_payload = false :: boolean(),					%% 46 - log_show_payload						-> Se true, imprime o payload no log
					expires :: non_neg_integer(),							%% 47 - expires									-> Cabeçalho HTTP expires
					cache_control :: binary(),								%% 48 - cache_control							-> Cabeçalho HTTP cache-control
					enable = false :: boolean(),							%% 49 - enable				
					content_type :: binary(),								%% 50 - content_type							-> Tipo de conteúdo (Ex.: application/json, application/pdf)
					path :: string(),										%% 51 - path									-> Local no disco para carregar arquivos estáticos
					filename :: binary(),									%% 52 - filename								-> Alguns serviços podem precisar informar um nome de arquivo
					redirect_url :: binary(),								%% 53 - redirect url						
					tcp_listen_address :: list(),							%% 54 - tcp_listen_address
					tcp_listen_address_t :: tuple(),						%% 55 - tcp_listen_address_t
					tcp_listen_prefix_interface_names :: list(string()),	%% 56 - tcp_listen_prefix_interface_names
					tcp_allowed_address :: list(),							%% 57 - tcp_allowed_address
					tcp_allowed_address_t :: tuple(),						%% 58 - tcp_allowed_address_t
					tcp_max_connections :: non_neg_integer(),				%% 59 - tcp_max_connections
					tcp_port :: non_neg_integer(),							%% 60 - tcp_port
					tcp_is_ssl :: boolean(),								%% 61 - tcp_is_ssl
					tcp_ssl_cacertfile :: binary(),							%% 62 - tcp_ssl_cacertfile
					tcp_ssl_certfile :: binary(),							%% 63 - tcp_ssl_certfile
					tcp_ssl_keyfile :: binary(),							%% 64 - tcp_ssl_keyfile
					protocol :: binary(),									%% 65 - protocol
					properties :: map(),									%% 66 - properties								-> Outros parâmetros
				    ctrl_path :: string(),									%% 67 - ctrl_path
					ctrl_file :: string(),									%% 68 - ctrl_file
					ctrl_insert :: binary(),								%% 69 - ctrl_insert								-> Data que foi inserido no banco mnesia
					ctrl_update :: binary(), 								%% 70 - ctrl_update								-> Data que foi atualiado no banco mnesia			
					ctrl_modified :: binary(),								%% 71 - ctrl_modified							-> Data que foi modificado na fonte onde está cadastrado (em disco ou banco de dados externo)
					ctrl_hash :: non_neg_integer(),							%% 72 - ctrl_hash 								-> Hash gerado para poder comparar dois registros	
					start_timeout :: non_neg_integer(),						%% 73 - start_timeout							-> Define um timeout inicial para aguardar antes de iniciar o processo do serviço
					service_exec_metric_name :: atom(),						%% 74 - service_exec_metric_name			
					service_result_cache_hit_metric_name :: atom(),			%% 75 - service_result_cache_hit_metric_name
					service_host_denied_metric_name :: atom(),				%% 76 - service_host_denied_metric_name
					service_auth_denied_metric_name :: atom(),				%% 77 - service_auth_denied_metric_name
					service_error_metric_name :: atom(),					%% 78 - service_error_metric_name
					service_unavailable_metric_name :: atom(),				%% 79 - service_unavailable_metric_name
					service_timeout_metric_name :: atom(),					%% 80 - service_timeout_metric_name
					service_resend_msg1 :: atom(),							%% 81 - service_resend_msg1
					http_max_content_length :: non_neg_integer(),			%% 82 - http_max_content_length
					http_headers :: map(),									%% 83 - http_headers
					restricted = false :: boolean(),						%% 84 - restricted								-> Serviço restrito aos admins
					glyphicon :: binary(),									%% 85 - glyphicon								-> classe css do glyphicon
					metadata :: binary(),									%% 86 - metadata 								-> Representação em json do que será enviado para o web service /catalog
					show_debug_response_headers = false :: boolean(),		%% 87 - show_debug_response_headers				-> Add debug headers in HTTP response headers
					result_cache_shared = true :: boolean(),				%% 88 - result_cache_shared						-> true if resulta cache is shared between requests
					log_show_response_header :: boolean()					%% 89 - result_cache_shared						-> true if show response header in logger
				}).


-define(SERVICE_DESCRIPTOR, {
			   atom_type,									%%  0 - nome da tabela	
			   non_neg_integer_type,						%%  1 - id
			   non_neg_integer_type,						%%  2 - rowid
			   binary_type,									%%  3 - name
			   binary_type, 	 							%%  4 - url										
			   binary_type,								 	%%  5 - type
			   binary_type,									%%  6 - service
			   atom_type,									%%  7 - middleware
			   string_type, 								%%  8 - module_name
			   string_type,	 								%%  9 - module_name_canonical
			   atom_type,  									%% 10 - module
			   string_type,									%% 11 - function_name
			   atom_type,									%% 12 - function
			   boolean_type,								%% 13 - use_re
			   undefined,									%% 14 - id_re_compiled
			   boolean_type, 								%% 15 - public
			   binary_type, 								%% 16 - comment
			   binary_type, 								%% 17 - version
			   binary_type,									%% 18 - owner
			   binary_type,									%% 19 - group
			   boolean_type,								%% 20 - async
			   undefined,									%% 21 - querystring
			   non_neg_integer_type,						%% 22 - qtd_querystring_req
			   atom_type,									%% 23 - host
			   binary_type,	  								%% 24 - host_name
			   non_neg_integer_type,						%% 25 - result_cache
			   atom_type,									%% 26 - authorization
			   boolean_type,								%% 27 - authorization_public_check_credential
			   boolean_type,								%% 28 - oauth2_with_check_constraint	
			   boolean_type,								%% 29 - oauth2_allow_client_credentials
			   boolean_type,								%% 30 - oauth2_token_encrypt
			   boolean_type,						  		%% 31 - auth_allow_user_inative_credentials
			   binary_type,									%% 32 - page
			   undefined,									%% 33 - page_module
			   binary_type,									%% 34 - page_mime_type
			   undefined,									%% 35 - node
			   binary_type,									%% 36 - lang
			   undefined,									%% 37 - datasource
			   boolean_type,								%% 38 - debug
			   non_neg_integer_type,						%% 39 - schema_in
			   non_neg_integer_type,						%% 40 - schema_out
			   non_neg_integer_type, 						%% 41 - pool_size
			   non_neg_integer_type,						%% 42 - pool_max
			   non_neg_integer_type, 						%% 43 - timeout
			   non_neg_integer_type, 			  			%% 44 - timeout_alert_threshold
			   boolean_type,								%% 45 - log_show_response
			   boolean_type,								%% 46 - log_show_payload
			   non_neg_integer_type,						%% 47 - expires
			   binary_type,									%% 48 - cache_control
			   boolean_type,								%% 49 - enable				
			   binary_type, 								%% 50 - content_type
			   string_type,									%% 51 - path
			   binary_type,									%% 52 - filename
			   binary_type,									%% 53 - redirect url						
			   undefined, 									%% 54 - tcp_listen_address
			   undefined,									%% 55 - tcp_listen_address_t
			   undefined, 									%% 56 - tcp_listen_prefix_interface_names
			   undefined, 									%% 57 - tcp_allowed_address
			   undefined, 									%% 58 - tcp_allowed_address_t
			   undefined, 									%% 59 - tcp_max_connections
			   non_neg_integer_type,						%% 60 - tcp_port
			   boolean_type, 								%% 61 - tcp_is_ssl
			   binary_type, 								%% 62 - tcp_ssl_cacertfile
			   binary_type, 								%% 63 - tcp_ssl_certfile
			   binary_type, 								%% 64 - tcp_ssl_keyfile
			   binary_type, 								%% 65 - protocol
			   undefined, 									%% 66 - properties
			   string_type,									%% 67 - ctrl_path
			   string_type, 								%% 68 - ctrl_file
			   binary_type, 								%% 69 - ctrl_insert
			   binary_type, 								%% 70 - ctrl_update
			   binary_type,									%% 71 - ctrl_modified
			   non_neg_integer_type,						%% 72 - ctrl_hash
			   non_neg_integer_type,						%% 73 - start_timeout
			   atom_type, 									%% 74 - service_exec_metric_name			
			   atom_type, 									%% 75 - service_result_cache_hit_metric_name
			   atom_type, 									%% 76 - service_host_denied_metric_name
			   atom_type, 									%% 77 - service_auth_denied_metric_name
			   atom_type, 									%% 78 - service_error_metric_name
			   atom_type, 									%% 79 - service_unavailable_metric_name
			   atom_type, 									%% 80 - service_timeout_metric_name
			   atom_type, 									%% 81 - service_resend_msg1
			   non_neg_integer_type,						%% 82 - http_max_content_length
			   undefined, 									%% 83 - http_headers
			   boolean_type,								%% 84 - restricted
			   binary_type,									%% 85 - glyphicon
			   binary_type,									%% 86 - metadata
			   boolean_type,								%% 87 - show_debug_response_headers
			   boolean_type,								%% 88 - result_cache_shared
			   boolean_type									%% 89 - log_show_response_header
		}).


			   
-record(request, {
					  rid  :: non_neg_integer(), 				%%  1 - rid    					Request ID (Identificador da requisição gerada automaticamente)
					  rowid :: non_neg_integer(),				%%  2 - rowid  					Identificador interno da requisição. Ver ems_util:hashsym_and_params
					  service :: #service{},					%%  3 - service					Contrato que estabelece o serviço que vai atender a requisição
					  timestamp :: calendar:date(), 			%%  4 - Timestamp 	
					  latency :: non_neg_integer(),				%%  5 - latency 				Tempo que levou para processar a requisição
					  code :: non_neg_integer(), 				%%  6 - code					Código de retorno HTTP (Ex.: 202 OK, 404 Não Encontrado)
					  reason :: atom(),							%%  7 - reason					Atom para indicar o erro ou status da requisição
					  reason_detail :: atom(),					%%  8 - reason_detail			Atom para indicar o erro ou status da requisição
					  reason_exception :: any(),				%%  9 - reason_exception		Registra a exception ocorrida em run time
					  type :: binary(),							%% 10 - type					Verbo HTTP (GET, POST, PUT, DELETE e OPTIONS)
					  operation :: atom(),						%% 11 - operation				Descreve a operação sendo realizada
					  uri :: binary(),							%% 12 - uri						URI da requisição do serviço
					  url :: string(),							%% 13 - url						URL da requisição do serviço
					  url_masked = false :: boolean(),			%% 14 - url_masked				Indica se a url está mascarada. Ex.: /erl.ms/L2F1dGgvY2xpZW50Lz9maWx0ZXI9InsgICJuYW1lIiA6ICJQb3N0bWFuIiB9Ig==
					  version :: string(),						%% 15 - version					Versão do cabeçalho HTTP
					  payload :: binary(),						%% 16 - payload					Corpo da requisição (aceita somente JSON)
					  payload_map :: map(),						%% 17 - payload_map				Corpo da requisição convertida para map após o parser e validação
					  querystring :: binary(),					%% 18 - querystring				Querystring da requisição
					  querystring_map :: map(),					%% 19 - querystring_map			Querystring convertida para map após o parser e validação
					  params_url :: map(),						%% 20 - params_url				Map com os parâmetros da URL
					  content_type_in :: binary(),				%% 21 - content_type_in			Tipo de conteúdo de entrada (Ex.: application/json)
					  content_type_out :: binary(),				%% 22 - content_type_out		Tipo de conteúdo de saída. (Ex.: application/json)
					  content_length :: non_neg_integer(), 		%% 23 - content_length			Largura da requisição
					  accept :: binary(),						%% 24 - accept					Parâmetro ACCEPT HTTP
					  user_agent :: binary(),					%% 25 - user_agent
					  user_agent_version :: binary(),			%% 26 - user_agent_version
					  accept_encoding :: binary(),				%% 27 - accept_encoding			Parâmetro ACCEPT_ENCODING HTTP
					  cache_control :: binary(),				%% 28 - cache_control			Parâmetro CACHE-CONTROL HTTP
					  etag :: binary(),							%% 29 - etag					Parâmetro ETag
					  if_modified_since :: binary(),			%% 30 - if_modified_since		Parâmetro If-Modified-Since
					  if_none_match :: binary(),			    %% 31 - if_none_match			Parâmetro If-None-Match
					  ip :: tuple(),							%% 32 - ip
					  ip_bin :: binary(),						%% 33 - ip_bin	
					  t1 :: non_neg_integer(),					%% 34 - t1						
					  authorization :: binary(),				%% 36 - authorization			Dados da autenticação da requisição
					  client :: #client{},						%% 37 - client
					  user :: #user{},							%% 38 - user			
					  node_exec :: pid(),						%% 39 - node_exec				Processo que executou a solicitação
					  worker_send :: pid(),						%% 40 - worker_send				Processo que solicitou a solicitação
					  status = req_processing :: atom(),		%% 41 - status					req_processing, req_done
					  protocol :: atom(),						%% 42 - protocol				Protocol (http, ldap)
					  protocol_bin :: binary(),					%% 43 - protocol_bin
					  port :: non_neg_integer(),				%% 44 - port		
					  result_cache = false :: boolean(),		%% 45 - result_cache
					  result_cache_rid :: non_neg_integer(),	%% 46 - result_cache_rid
					  response_data = <<>> :: binary(),			%% 47 - response_data
					  response_header = #{} :: map(),			%% 48 - response_header
					  req_hash :: non_neg_integer(),			%% 49 - req_hash				Hash gerado para comparar requisições. Função utilizada: erlang:phash2
					  host :: binary(),							%% 50 - host
					  filename :: string(),						%% 51 - filename				Qual arquivo foi lido do disco para requisições que leêm arquivos no disco
					  referer :: binary(),						%% 52 - referer
					  access_token :: binary(),					%% 53 - access_token
					  scope :: binary(),						%% 54 - scope
					  oauth2_grant_type :: binary(),			%% 55 - oauth2_grant_type
					  oauth2_access_token :: binary(),			%% 56 - oauth2_access_token
					  oauth2_refresh_token :: binary(),			%% 57 - oauth2_refresh_token
					  status_text :: binary()					%% 58 - status_text				Status exibido no log 
				  }).


-record(ctrl_sqlite_table, {file_name :: string(), 
							last_modified :: file:date_time()}).
					

-record(catalog_schema, {id :: non_neg_integer(), 
						 name :: string(),	
						 description :: string(),
						 json_schema :: map()
						}).

-record(schema_type, {id :: non_neg_integer(), 
					  name :: string(),	
					  description :: string(),
					  json_schema :: map()
				}).


-record(stat_counter_hist, {  id :: non_neg_integer(),				%% 1 - id
							  stat_name :: atom(),					%% 2 - stat_name
							  stat_value :: non_neg_integer,		%% 3 - stat_value
							  stat_date :: binary(),				%% 4 - stat_date
							  stat_time :: binary(),				%% 5 - stat_time
							  stat_service_name :: binary(),		%% 6 - stat_service_name
							  stat_service_url :: binary(),			%% 7 - stat_service_url
							  stat_service_type :: binary(),		%% 8 - stat_service_type
							  stat_label :: binary()				%% 9 - stat_label
							}).


-define(STAT_COUNTER_HIST_DESCRIPTOR, {
			   atom_type,									%%  0 - nome da tabela	
			   non_neg_integer_type,						%%  1 - id
			   atom_type, 									%%  2 - stat_name   
			   non_neg_integer_type,						%%  3 - stat_value
			   binary_type,									%%  4 - stat_date
			   binary_type,									%%  5 - stat_time
			   binary_type,									%%  6 - stat_service_name
			   binary_type,									%%  7 - stat_service_url
			   binary_type,									%%  8 - stat_service_type
			   binary_type									%%  9 - stat_label
		}).


-record(auth_oauth2_access_token, { id :: binary(),
									context :: binary()
								  }).

-record(auth_oauth2_access_code, { id :: binary(),
								   context :: binary()
								 }).

-record(auth_oauth2_refresh_token, { id :: binary(),
									 context :: binary()
									}).

		
