%%********************************************************************
%% @title Module ems_user_loader_middleware
%% @version 1.0.0
%% @doc Module responsible for load users
%% @author Everton de Vargas Agilar <evertonagilar@gmail.com>
%% @copyright ErlangMS Team
%%********************************************************************

-module(ems_user_loader_middleware).

-include("include/ems_config.hrl").
-include("include/ems_schema.hrl").

-export([insert_or_update/5, 
		 is_empty/1, 
		 size_table/1, 
		 clear_table/1, 
		 reset_sequence/1, 
		 get_filename/0, 
		 check_remove_records/2, 
		 after_load_or_update_checkpoint/1]).


-spec is_empty(atom()) -> boolean().
is_empty(user_db) -> mnesia:table_info(user_db, size) == 0;
is_empty(user_aluno_ativo_db) -> mnesia:table_info(user_aluno_ativo_db, size) == 0;
is_empty(user_aluno_inativo_db) ->	mnesia:table_info(user_aluno_inativo_db, size) == 0;
is_empty(user_fs) -> mnesia:table_info(user_fs, size) == 0;
is_empty(user2_db) -> mnesia:table_info(user2_db, size) == 0;
is_empty(user3_db) -> mnesia:table_info(user3_db, size) == 0.
	

-spec size_table(atom()) -> non_neg_integer().
size_table(user_db) -> mnesia:table_info(user_db, size);
size_table(user_aluno_ativo_db) -> mnesia:table_info(user__, size);
size_table(user_aluno_inativo_db) -> mnesia:table_info(user_aluno_inativo_db, size);
size_table(user_fs) -> mnesia:table_info(user_fs, size);
size_table(user2_db) -> mnesia:table_info(user2_db, size);
size_table(user3_db) -> mnesia:table_info(user3_db, size).
	

-spec clear_table(atom()) -> ok | {error, efail_clear_ets_table}.
clear_table(SourceType) ->	
	case mnesia:clear_table(SourceType) of
		{atomic, ok} -> 
			mnesia:clear_table(user_cache_lru),
			ok;
		_ -> {error, efail_clear_ets_table}
	end.
	
	
-spec reset_sequence(user_db | user_aluno_ativo_db | user_aluno_inativo_db | user_fs) -> ok.
reset_sequence(_) -> ok.
	
	
-spec check_remove_records(list(), fs | db) -> non_neg_integer().	
check_remove_records(_Codigos, _SourceType) -> 0.
	

-spec get_filename() -> list(tuple()).
get_filename() -> 
	Conf = ems_config:getConfig(),
	Conf#config.user_path_search.
	
	
-spec insert_or_update(map() | tuple(), tuple(), #config{}, atom(), insert | update) -> {ok, #service{}, atom(), insert | update} | {ok, skip} | {error, atom()}.
insert_or_update(Map, CtrlDate, Conf, SourceType, Operation) ->
	try
		case ems_user:new_from_map(Map, Conf) of
			{ok, NewUser = #user{id = Id, ctrl_hash = CtrlHash}} -> 
				case ems_user:find(SourceType, Id) of
					{error, enoent} -> 
						User = NewUser#user{ctrl_insert = CtrlDate, 
											ctrl_source_type = SourceType},
						ems_db:delete(user_cache_lru, Id),
						notify_java_user_service(Conf, User, Operation),
						{ok, User, SourceType, insert};
					{ok, CurrentUser = #user{ctrl_hash = CurrentCtrlHash}} ->
						case CtrlHash =/= CurrentCtrlHash of
							true ->
								?DEBUG("ems_user_loader_middleware update ~p from ~p.", [Map, SourceType]),
								%type, subtype são atualizado somente pelo dataloader de dados funcionais
							   
							    OldLogin = case NewUser#user.login =/= CurrentUser#user.login of
												true -> CurrentUser#user.login;
												false -> CurrentUser#user.old_login
										   end,

							    OldName = case NewUser#user.name =/= CurrentUser#user.name of
												true -> CurrentUser#user.name;
												false -> CurrentUser#user.old_name
										  end,

							    OldCpf = case NewUser#user.cpf =/= CurrentUser#user.cpf of
												true -> CurrentUser#user.cpf;
												false -> CurrentUser#user.old_cpf
										  end,

							    OldEmail = case NewUser#user.email =/= CurrentUser#user.email of
												true -> CurrentUser#user.email;
												false -> CurrentUser#user.old_email
										  end,

							    OldPassword = case NewUser#user.password =/= CurrentUser#user.password of
												true -> CurrentUser#user.password;
												false -> CurrentUser#user.old_password
										  end,

								User = CurrentUser#user{
												 codigo = NewUser#user.codigo,
												 login = NewUser#user.login,
												 name = NewUser#user.name,
												 cpf = NewUser#user.cpf,
												 password = NewUser#user.password,
												 passwd_crypto = NewUser#user.passwd_crypto,
												 dt_expire_password = NewUser#user.dt_expire_password,
												 endereco = NewUser#user.endereco,
												 complemento_endereco = NewUser#user.complemento_endereco,
												 bairro = NewUser#user.bairro,
												 cidade = NewUser#user.cidade,
												 uf = NewUser#user.uf,
												 cep = NewUser#user.cep,
												 rg = NewUser#user.rg,
												 data_nascimento = NewUser#user.data_nascimento,
												 sexo = NewUser#user.sexo,
												 telefone = NewUser#user.telefone,
												 celular = NewUser#user.celular,
												 ddd = NewUser#user.ddd,
												 email = NewUser#user.email,
												 nome_pai = NewUser#user.nome_pai,
												 nome_mae = NewUser#user.nome_mae,
												 nacionalidade = NewUser#user.nacionalidade,
												 remap_user_id = NewUser#user.remap_user_id,
												 admin = NewUser#user.admin,
												 active = NewUser#user.active,
												 old_login = OldLogin,
												 old_name = OldName,
												 old_cpf = OldCpf,
												 old_email = OldEmail,
												 old_password = OldPassword,
												 ctrl_path = NewUser#user.ctrl_path,
												 ctrl_file = NewUser#user.ctrl_file,
												 ctrl_update = CtrlDate,
												 ctrl_modified = NewUser#user.ctrl_modified,
												 ctrl_hash = NewUser#user.ctrl_hash,
												 ctrl_source_type = SourceType
											},
								ems_db:delete(user_cache_lru, Id),
								notify_java_user_service(Conf, User, Operation),
								{ok, User, SourceType, update};
							false -> 
								notify_java_user_service(Conf, CurrentUser, Operation),
								{ok, skip}
						end
				end;
			Error -> Error
		end

	catch
		_Exception:Reason -> {error, Reason}
	end.


notify_java_user_service(Conf, User, Operation) ->
	case Conf#config.java_service_user_notify =/= undefined andalso 
		 Conf#config.java_service_user_notify_node =/= undefined andalso 
		 Conf#config.java_service_user_notify_module =/= undefined andalso 
		 Conf#config.java_service_user_notify_function =/= undefined andalso 
		 ((Conf#config.java_service_user_notify_on_load_enabled andalso Operation == insert)
		   orelse
		   (Conf#config.java_service_user_notify_on_update_enabled andalso Operation == update)
		   orelse
		   Conf#config.java_service_user_notify_full_sync_enabled
		 )
		 of
		true ->	
			try
				%% Somente envia a mensagem se os requisitos abaixo forem atingidos
				case User#user.type > 0 andalso
					 lists:member(User#user.ctrl_source_type, Conf#config.java_service_user_notify_source_types) andalso
					 User#user.password =/= <<>> andalso 
					 User#user.active == true andalso
					 (User#user.nome_mae =/= <<>> orelse (User#user.nome_mae == <<>> andalso not lists:member(nome_mae, Conf#config.java_service_user_notify_required_fields))) andalso
					 (User#user.cpf =/= <<>> orelse (User#user.cpf == <<>> andalso not lists:member(cpf, Conf#config.java_service_user_notify_required_fields))) andalso
					 (User#user.email =/= <<>> orelse (User#user.email == <<>> andalso not lists:member(email, Conf#config.java_service_user_notify_required_fields))) of
					true ->
						ems_user_notify_service:add(User);
					false ->  
						ok
				end
			catch
				_Exception:Reason -> 
					% Não propaga exceptions, apenas emite uma mensagem no log
					ems_logger:error("ems_user_loader_middleware /netadm/dataloader/user/notify failed. Reason: ~p.", [Reason]) ,
					ok
			end;
		false -> ok
	end.
	
			


-spec after_load_or_update_checkpoint(fs | db) -> ok.
after_load_or_update_checkpoint(_SourceType) ->	ok.

