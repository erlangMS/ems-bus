%%********************************************************************
%% @title Module ems_data_loader_service
%% @version 1.0.0
%% @doc It provides web services to administer data loaders
%% @author Everton de Vargas Agilar <evertonagilar@gmail.com>
%% @copyright ErlangMS Team
%%********************tn************************************************

-module(ems_data_loader_service).

-include("include/ems_config.hrl").
-include("include/ems_schema.hrl").

-export([sync/1, sync_full/1]).
  
sync(Request) -> 
	case ems_util:get_param_url(<<"name">>, undefined, Request) of
		<<"client">> ->
			ems_data_loader:sync(ems_client_loader_db),
			ems_json_loader:sync(ems_client_loader_fs),
			{ok, Request#request{code = 200, 
								 response_data = ?OK_JSON}
			};
		<<"user">> ->
			ems_data_loader:sync(ems_user_loader_db),
			ems_json_loader:sync(ems_user_loader_fs),
			{ok, Request#request{code = 200, 
								 response_data = ?OK_JSON}
			};
		<<"user/perfil">> ->
			ems_data_loader:sync(ems_user_perfil_loader_db),
			ems_json_loader:sync(ems_user_perfil_loader_fs),
			{ok, Request#request{code = 200, 
								 response_data = ?OK_JSON}
			};
		<<"user/permission">> ->
			ems_data_loader:sync(ems_user_permission_loader_db),
			ems_json_loader:sync(ems_user_permission_loader_fs),
			{ok, Request#request{code = 200, 
								 response_data = ?OK_JSON}
			};
		<<"user/telefone">> ->
			ems_data_loader:sync(ems_user_telefone_loader_db),
			ems_json_loader:sync(ems_user_telefone_loader_fs),
			{ok, Request#request{code = 200, 
								 response_data = ?OK_JSON}
			};
		<<"user/email">> ->
			ems_data_loader:sync(ems_user_email_loader_db),
			ems_json_loader:sync(ems_user_email_loader_fs),
			{ok, Request#request{code = 200, 
								 response_data = ?OK_JSON}
			};
		<<"user/dados_funcionais">> ->
			ems_data_loader:sync(ems_user_dados_funcionais_loader_db),
			ems_json_loader:sync(ems_user_dados_funcionais_loader_fs),
			{ok, Request#request{code = 200, 
								 response_data = ?OK_JSON}
			};
		<<"aluno">> ->
			ems_data_loader:sync(ems_user_aluno_ativo_loader_db),
			ems_data_loader:sync(ems_user_aluno_inativo_loader_db),
			{ok, Request#request{code = 200, 
								 response_data = ?OK_JSON}
			};
		<<"aluno/ativo">> ->
			ems_data_loader:sync(ems_user_aluno_ativo_loader_db),
			{ok, Request#request{code = 200, 
								 response_data = ?OK_JSON}
			};
		<<"aluno/inativo">> ->
			ems_data_loader:sync(ems_user_aluno_inativo_loader_db),
			{ok, Request#request{code = 200, 
								 response_data = ?OK_JSON}
			};
		_ -> 
			{error, Request#request{code = 400, 
									response_data = ?EINVALID_DATA_LOADER}
			}
	end.
			
sync_full(Request) -> 
	case ems_util:get_param_url(<<"name">>, undefined, Request) of
		<<"client">> ->
			io:format("Chegou aqui sync_full >>>>>>>>>>>>>>>>>>>>>>>>>>>> ~n~n"),
			ems_data_loader:sync_full(ems_client_loader_db),
			ems_json_loader:sync_full(ems_client_loader_fs),
			{ok, Request#request{code = 200, 
								 response_data = ?OK_JSON}
			};
		<<"user">> ->
			ems_data_loader:sync_full(ems_user_loader_db),
			ems_json_loader:sync_full(ems_user_loader_fs),
			{ok, Request#request{code = 200, 
								 response_data = ?OK_JSON}
			};
		<<"user/perfil">> ->
			ems_data_loader:sync_full(ems_user_perfil_loader_db),
			ems_json_loader:sync_full(ems_user_perfil_loader_fs),
			{ok, Request#request{code = 200, 
								 response_data = ?OK_JSON}
			};
		<<"user/permission">> ->
			ems_data_loader:sync_full(ems_user_permission_loader_db),
			ems_json_loader:sync_full(ems_user_permission_loader_fs),
			{ok, Request#request{code = 200, 
								 response_data = ?OK_JSON}
			};
		<<"user/telefone">> ->
			ems_data_loader:sync_full(ems_user_telefone_loader_db),
			ems_json_loader:sync_full(ems_user_telefone_loader_fs),
			{ok, Request#request{code = 200, 
								 response_data = ?OK_JSON}
			};
		<<"user/email">> ->
			ems_data_loader:sync_full(ems_user_email_loader_db),
			ems_json_loader:sync_full(ems_user_email_loader_fs),
			{ok, Request#request{code = 200, 
								 response_data = ?OK_JSON}
			};
		<<"user/dados_funcionais">> ->
			ems_data_loader:sync_full(ems_user_dados_funcionais_loader_db),
			ems_json_loader:sync_full(ems_user_dados_funcionais_loader_fs),
			{ok, Request#request{code = 200, 
								 response_data = ?OK_JSON}
			};
		<<"aluno">> ->
			ems_data_loader:sync_full(ems_user_aluno_ativo_loader_db),
			ems_data_loader:sync_full(ems_user_aluno_inativo_loader_db),
			{ok, Request#request{code = 200, 
								 response_data = ?OK_JSON}
			};
		<<"aluno/ativo">> ->
			ems_data_loader:sync_full(ems_user_aluno_ativo_loader_db),
			{ok, Request#request{code = 200, 
								 response_data = ?OK_JSON}
			};
		<<"aluno/inativo">> ->
			ems_data_loader:sync_full(ems_user_aluno_inativo_loader_db),
			{ok, Request#request{code = 200, 
								 response_data = ?OK_JSON}
			};				
		_ -> 
			{error, Request#request{code = 400, 
									response_data = ?EINVALID_DATA_LOADER}
			}
	end.
