%%********************************************************************
%% @title Module ems_user
%% @version 1.0.0
%% @doc user class
%% @author Everton de Vargas Agilar <evertonagilar@gmail.com>
%% @copyright ErlangMS Team
%%********************************************************************

-module(ems_user).

-include("include/ems_config.hrl").
-include("include/ems_schema.hrl").
-include_lib("stdlib/include/qlc.hrl").

-export([find_by_id/1,		 
		 find_by_login/1, 
		 find_by_name/1, 
		 find_by_email/1, 
		 find_by_cpf/1, 
		 find_by_login_and_password/2,
		 find_by_login_and_password/3,
		 find_by_codigo_pessoa/1, 
		 find_by_codigo_pessoa/2,
		 find_by_filter/2,
		 to_resource_owner/1,
		 to_resource_owner/2,
 		 new_from_map/2,
		 get_table/1,
		 find/2,
		 exist/2,
		 all/0,
		 all/1,
		 add_history/1,
		 add_history/3,
		 add_history/4,
		 get_admim_user/0]).


-spec find_by_id(non_neg_integer()) -> {ok, #user{}} | {error, enoent}.
find_by_id(Id) -> 
	case ems_db:get([user_db, user2_db, user_aluno_ativo_db, user_aluno_inativo_db, user_fs], Id) of
		{ok, Record} -> {ok, Record};
		_ -> {error, enoent}
	end.

-spec all() -> {ok, list()}.
all() -> 
	{ok, ListaUserDb} = ems_db:all(user_db),
	{ok, ListaUser2Db} = ems_db:all(user2_db),
	{ok, ListaUserAlunoAtivoDb} = ems_db:all(user_aluno_ativo_db),
	{ok, ListaUserAlunoInativoDb} = ems_db:all(user_aluno_inativo_db),
	{ok, ListaUserFs} = ems_db:all(user_fs),
	{ok, ListaUserDb ++ ListaUser2Db ++ ListaUserAlunoAtivoDb ++ ListaUserAlunoInativoDb ++ ListaUserFs}.
	

-spec find_by_filter(list(binary()), tuple()) -> {ok, list(#user{})} | {error, atom(), atom()}.
find_by_filter(Fields, Filter) -> 
	ems_db:find([user_db, user2_db, user_aluno_ativo_db, user_aluno_inativo_db, user_fs], Fields, Filter).



-spec find_by_codigo_pessoa(non_neg_integer()) -> {ok, list(#user{})} | {error, enoent}.
find_by_codigo_pessoa(Codigo) ->
	case Codigo > 0 of
		true ->
			case mnesia:dirty_index_read(user_db, Codigo, #user.codigo) of
				[] -> 
					case mnesia:dirty_index_read(user2_db, Codigo, #user.codigo) of
						[] -> 
							case mnesia:dirty_index_read(user_aluno_ativo_db, Codigo, #user.codigo) of
									[] -> 
										case mnesia:dirty_index_read(user_aluno_inativo_db, Codigo, #user.codigo) of
											[] -> case mnesia:dirty_index_read(user_fs, Codigo, #user.codigo) of
													[] -> {error, enoent};
													Records -> {ok, Records}
												  end;
											Records -> {ok, Records}
										end;
									Records -> {ok, Records}
								  end;
						Records -> {ok, Records}
					end;
				Records -> {ok, Records}
			end;
		false -> {error, enoent}
	end.


-spec find_by_codigo_pessoa(atom(), non_neg_integer()) -> {ok, list(#user{})} | {error, enoent}.
find_by_codigo_pessoa(Table, Codigo) ->
	case mnesia:dirty_index_read(Table, Codigo, #user.codigo) of
		[] -> {error, enoent};
		Records -> {ok, Records}
	end.


find_index_by_login_and_password_cmp_password(_, [], _, _, _, _, _, _, _, _, _, _, _, _, _,_,_) ->
	{error, access_denied};
find_index_by_login_and_password_cmp_password([Table|_] = Tables, 
											[#user{password = PasswordUser, cpf = Cpf, ctrl_last_login_scope = CtrlLoginScope} = User|T], 
											LoginBin, 
											PasswordBin, 
											PasswordBinCryptoSHA1, 
											PasswordBinLowerCryptoSHA1, 
											PasswordBinUpperCryptoSHA1, 
											PasswordBinCryptoMD5, 
											PasswordBinLowerCryptoMD5, 
											PasswordBinUpperCryptoMD5, 
											PasswordBinCryptoBLOWFISH, 
											PasswordBinLowerCryptoBLOWFISH, 
											PasswordBinUpperCryptoBLOWFISH, 
											PasswordStrLower, 
											PasswordStrUpper, 
											Client,
											AuthPasswordCheckBetweenScope) ->
	case PasswordUser =:= PasswordBinCryptoSHA1 
		 orelse PasswordUser =:= PasswordBin 
		 orelse PasswordUser =:= PasswordBinLowerCryptoSHA1 
		 orelse PasswordUser =:= PasswordBinUpperCryptoSHA1 
		 orelse PasswordUser =:= PasswordBinCryptoMD5 
		 orelse PasswordUser =:= PasswordBinLowerCryptoMD5 
		 orelse PasswordUser =:= PasswordBinUpperCryptoMD5 
		 orelse PasswordUser =:= PasswordBinCryptoBLOWFISH 
		 orelse PasswordUser =:= PasswordBinLowerCryptoBLOWFISH 
		 orelse PasswordUser =:= PasswordBinUpperCryptoBLOWFISH 
		 orelse PasswordUser =:= PasswordStrLower 
		 orelse PasswordUser =:= PasswordStrUpper of
			true -> 
				case Table of
					user_cache_lru ->
						User2 = User#user{ctrl_last_login = ems_util:timestamp_binary(), 
										  ctrl_login_count = User#user.ctrl_login_count + 1,
										  ctrl_last_login_client = Client#client.name},
						mnesia:dirty_write(user_cache_lru, User2),
						case CtrlLoginScope of
							undefined -> ok; % não deveria se está no cache lru
							_ -> mnesia:dirty_write(CtrlLoginScope, User2)
						end;
					_ -> 
						User2 = User#user{ctrl_last_login = ems_util:timestamp_binary(), 
										  ctrl_login_count = User#user.ctrl_login_count + 1,
										  ctrl_last_login_scope = Table,
										  ctrl_last_login_client = Client#client.name},
						mnesia:dirty_write(user_cache_lru, User2),
						mnesia:dirty_write(Table, User2)
				end,	
				{ok, User2};
			false -> 
				% Eh tabela user_aluno_ativo_db e encontrou o login mas não bateu a senha, vamos tentar buscar a 
				% senha na tabela user_db (se a tabela user_db também está no scope)
				case Table == user_aluno_ativo_db andalso AuthPasswordCheckBetweenScope of
					true -> 
						case mnesia:dirty_index_read(user_db, LoginBin, #user.login) of
							[#user{password = PasswordUserEmOutraTabela, cpf = CpfUserEmOutraTabela}|_] -> 
								case CpfUserEmOutraTabela =:= Cpf andalso 
									(
										PasswordUserEmOutraTabela =:= PasswordBinCryptoSHA1 
										 orelse PasswordUserEmOutraTabela =:= PasswordBin 
										 orelse PasswordUserEmOutraTabela =:= PasswordBinLowerCryptoSHA1 
										 orelse PasswordUserEmOutraTabela =:= PasswordBinUpperCryptoSHA1 
										 orelse PasswordUserEmOutraTabela =:= PasswordBinCryptoMD5 
										 orelse PasswordUserEmOutraTabela =:= PasswordBinLowerCryptoMD5 
										 orelse PasswordUserEmOutraTabela =:= PasswordBinUpperCryptoMD5 
										 orelse PasswordUserEmOutraTabela =:= PasswordBinCryptoBLOWFISH 
										 orelse PasswordUserEmOutraTabela =:= PasswordBinLowerCryptoBLOWFISH 
										 orelse PasswordUserEmOutraTabela =:= PasswordBinUpperCryptoBLOWFISH 
										 orelse PasswordUserEmOutraTabela =:= PasswordStrLower 
										 orelse PasswordUserEmOutraTabela =:= PasswordStrUpper
									 ) of
										true -> 
											case Table of
												user_cache_lru ->
													User2 = User#user{ctrl_last_login = ems_util:timestamp_binary(), 
																	  ctrl_login_count = User#user.ctrl_login_count + 1,
																	  ctrl_last_login_client = Client#client.name},
													mnesia:dirty_write(user_cache_lru, User2),
													case CtrlLoginScope of
														undefined -> ok; % não deveria se está no cache lru
														_ -> mnesia:dirty_write(CtrlLoginScope, User2)
													end;
												_ -> 
													User2 = User#user{ctrl_last_login = ems_util:timestamp_binary(), 
																	  ctrl_login_count = User#user.ctrl_login_count + 1,
																	  ctrl_last_login_scope = Table,
																	  ctrl_last_login_client = Client#client.name},
													mnesia:dirty_write(user_cache_lru, User2),
													mnesia:dirty_write(Table, User2)
											end,	
											{ok, User2};
										false -> 
											find_index_by_login_and_password_cmp_password(Tables, T, LoginBin, 
																PasswordBin, 
																PasswordBinCryptoSHA1, PasswordBinLowerCryptoSHA1, PasswordBinUpperCryptoSHA1, 
																PasswordBinCryptoMD5, PasswordBinLowerCryptoMD5, PasswordBinUpperCryptoMD5, 
																PasswordBinCryptoBLOWFISH, PasswordBinLowerCryptoBLOWFISH, PasswordBinUpperCryptoBLOWFISH, 
																PasswordStrLower, PasswordStrUpper, Client,AuthPasswordCheckBetweenScope) 
									end
								end;
					false ->					
						find_index_by_login_and_password_cmp_password(Tables, T, LoginBin, 
											PasswordBin, 
											PasswordBinCryptoSHA1, PasswordBinLowerCryptoSHA1, PasswordBinUpperCryptoSHA1, 
											PasswordBinCryptoMD5, PasswordBinLowerCryptoMD5, PasswordBinUpperCryptoMD5, 
											PasswordBinCryptoBLOWFISH, PasswordBinLowerCryptoBLOWFISH, PasswordBinUpperCryptoBLOWFISH, 
											PasswordStrLower, PasswordStrUpper, Client,AuthPasswordCheckBetweenScope) 
				end
	end.


find_index_by_login_and_password([], _, _, _, _, _, _, _, _, _, _, _, _, _, _, _) ->
	ems_data_loader:sync(ems_user_loader_db),
	{error, access_denied, enoent};
find_index_by_login_and_password([Table|T] = Tables, 
											LoginBin, 
											PasswordBin, 
											PasswordBinCryptoSHA1, 
											PasswordBinLowerCryptoSHA1, 
											PasswordBinUpperCryptoSHA1, 
											PasswordBinCryptoMD5, 
											PasswordBinLowerCryptoMD5, 
											PasswordBinUpperCryptoMD5, 
											PasswordBinCryptoBLOWFISH, 
											PasswordBinLowerCryptoBLOWFISH, 
											PasswordBinUpperCryptoBLOWFISH, 
											PasswordStrLower, 
											PasswordStrUpper, 
											Client,
											AuthPasswordCheckBetweenScope) ->
	case mnesia:dirty_index_read(Table, LoginBin, #user.login) of
		Users when is_list(Users) -> 
			case find_index_by_login_and_password_cmp_password(Tables, Users, LoginBin, 
																PasswordBin, 
																PasswordBinCryptoSHA1, PasswordBinLowerCryptoSHA1, PasswordBinUpperCryptoSHA1, 
																PasswordBinCryptoMD5, PasswordBinLowerCryptoMD5, PasswordBinUpperCryptoMD5, 
																PasswordBinCryptoBLOWFISH, PasswordBinLowerCryptoBLOWFISH, PasswordBinUpperCryptoBLOWFISH, 
																PasswordStrLower, PasswordStrUpper, Client, AuthPasswordCheckBetweenScope) of
				{ok, User} -> {ok, User};
				{error, access_denied} -> 
					find_index_by_login_and_password(T, LoginBin, 
												PasswordBin, 
												PasswordBinCryptoSHA1, PasswordBinLowerCryptoSHA1, PasswordBinUpperCryptoSHA1, 
												PasswordBinCryptoMD5, PasswordBinLowerCryptoMD5, PasswordBinUpperCryptoMD5, 
												PasswordBinCryptoBLOWFISH, PasswordBinLowerCryptoBLOWFISH, PasswordBinUpperCryptoBLOWFISH, 
												PasswordStrLower, PasswordStrUpper, Client, AuthPasswordCheckBetweenScope)
			end;
		_ -> 
			find_index_by_login_and_password(T, LoginBin, 
							PasswordBin, 
							PasswordBinCryptoSHA1, PasswordBinLowerCryptoSHA1, PasswordBinUpperCryptoSHA1, 
							PasswordBinCryptoMD5, PasswordBinLowerCryptoMD5, PasswordBinUpperCryptoMD5, 
							PasswordBinCryptoBLOWFISH, PasswordBinLowerCryptoBLOWFISH, PasswordBinUpperCryptoBLOWFISH, 
							PasswordStrLower, PasswordStrUpper, Client, AuthPasswordCheckBetweenScope)
	end.

-spec find_by_login_and_password(binary() | list(), binary() | list()) -> {ok, #user{}} | {error, access_denied, enoent | einvalid_password}.	
find_by_login_and_password(Login, Password) -> find_by_login_and_password(Login, Password, undefined). 


-spec find_by_login_and_password(binary() | list(), binary() | list(), #client{}) -> {ok, #user{}} | {error, access_denied, enoent | einvalid_password}.	
find_by_login_and_password(_, <<>>, _) -> {error, access_denied, epassword_empty};
find_by_login_and_password(<<>>, _, _) -> {error, access_denied, elogin_empty};
find_by_login_and_password(_, "", _) -> {error, access_denied, epassword_empty};
find_by_login_and_password("", _, _) -> {error, access_denied, elogin_empty};
find_by_login_and_password(Login, Password, Client)  ->
	PasswordStr = case is_list(Password) of
					 true -> Password;
					 false -> binary_to_list(Password)
				  end,
	PasswordSize = length(PasswordStr),
	case PasswordSize >= 0 andalso PasswordSize =< 256 of
		true ->
			LoginStr = case is_list(Login) of
							true -> string:to_lower(Login);
							false -> string:to_lower(binary_to_list(Login))
					   end,
			LoginBin = list_to_binary(LoginStr),
			PasswordBin = list_to_binary(PasswordStr),

			PasswordStrLower = string:to_lower(PasswordStr),
			PasswordStrUpper = string:to_upper(PasswordStr),

			PasswordBinCryptoSHA1 = ems_util:criptografia_sha1(PasswordStr),
			PasswordBinLowerCryptoSHA1 = ems_util:criptografia_sha1(PasswordStrLower),
			PasswordBinUpperCryptoSHA1 = ems_util:criptografia_sha1(PasswordStrUpper),

			PasswordBinCryptoMD5 = ems_util:criptografia_md5(PasswordStr),
			PasswordBinLowerCryptoMD5 = ems_util:criptografia_md5(PasswordStrLower),
			PasswordBinUpperCryptoMD5 = ems_util:criptografia_md5(PasswordStrUpper),

			case ems_db:get_param(use_blowfish_crypto) of
				true ->
					PasswordBinCryptoBLOWFISH = ems_util:criptografia_blowfish(PasswordStr),
					PasswordBinLowerCryptoBLOWFISH = ems_util:criptografia_blowfish(PasswordStrLower),
					PasswordBinUpperCryptoBLOWFISH = ems_util:criptografia_blowfish(PasswordStrUpper);
				false ->
					PasswordBinCryptoBLOWFISH = undefined,
					PasswordBinLowerCryptoBLOWFISH = undefined,
					PasswordBinUpperCryptoBLOWFISH = undefined
			end,

			case Client of
				undefined -> 
					TablesScope = ems_util:get_auth_default_scope(),
					Client2 = #client{id = 0, name = <<"public">>, scope = TablesScope};
				_ -> 
					TablesScope = Client#client.scope,
					Client2 = Client
			end,

			% A verificação de senhas entre scopes eh somente em user_aluno_ativo_db e user_db
			AuthPasswordCheckBetweenScope = ems_db:get_param(auth_password_check_between_scope) and lists:member(user_db, TablesScope) == true,
			
			case find_index_by_login_and_password(TablesScope, 
											 LoginBin, 
											 PasswordBin, 
											 PasswordBinCryptoSHA1, 
											 PasswordBinLowerCryptoSHA1, 
											 PasswordBinUpperCryptoSHA1, 
											 PasswordBinCryptoMD5, 
											 PasswordBinLowerCryptoMD5, 
											 PasswordBinUpperCryptoMD5, 
											 PasswordBinCryptoBLOWFISH, 
											 PasswordBinLowerCryptoBLOWFISH, 
											 PasswordBinUpperCryptoBLOWFISH, 
											 PasswordStrLower, 
											 PasswordStrUpper,
											 Client2,
											 AuthPasswordCheckBetweenScope) of
				{ok, #user{ctrl_source_type = CtrlSourceType} = User} ->
					ems_logger:info("ems_user find_by_login_and_password success (Login: ~p CtrlSourceType: ~w Client: ~p ~s).", [Login, CtrlSourceType, Client2#client.id, binary_to_list(Client2#client.name)]),
					{ok, User};					
				Error ->
					% Se o login apresenta o sufixo de e-mail, remove e pesquisa novamente
					SufixoEmailInstitucional = ems_db:get_param(sufixo_email_institucional),
					io:format("SufixoEmailInstitucional is ~p  tem ~p\n", [SufixoEmailInstitucional, lists:suffix(SufixoEmailInstitucional, LoginStr)]),
					case lists:suffix(SufixoEmailInstitucional, LoginStr) of
						 true ->
							LoginStrSemSufixo = string:substr(LoginStr, 1, length(LoginStr)-length(SufixoEmailInstitucional)),
							find_by_login_and_password(LoginStrSemSufixo, Password, Client2);
						 false -> 
							ems_logger:warn("ems_user find_by_login_and_password failed (Login: ~p AuthScopes: ~w Client: ~p ~s).", [Login, TablesScope, Client2#client.id, binary_to_list(Client2#client.name)]),
							Error
					end
			end;
		false -> 
			{error, access_denied, einvalid_password_size}
	end.

	

-spec find_by_login(binary() | string()) -> {ok, #user{}} | {error, access_denied, enoent | elogin_empty}.
find_by_login(<<>>) -> {error, access_denied, elogin_empty};	
find_by_login("") -> {error, access_denied, elogin_empty};	
find_by_login(undefined) -> {error, access_denied, elogin_empty};	
find_by_login(Login) ->
	LoginStr = case is_list(Login) of
					true -> string:to_lower(Login);
					false -> string:to_lower(binary_to_list(Login))
			   end,
	LoginBin = list_to_binary(LoginStr),
	IndexFind = fun(Table) ->
		case mnesia:dirty_index_read(Table, LoginBin, #user.login) of
			[User|_] -> {ok, User};
			_ -> {error, enoent}
		end
	end,
	case IndexFind(user_cache_lru) of
		{error, enoent} -> 
			case IndexFind(user_db) of
				{error, enoent} -> 
					case IndexFind(user2_db) of
						{error, enoent} -> 
							case IndexFind(user_aluno_ativo_db) of
								{error, enoent} -> 
									case IndexFind(user_aluno_inativo_db) of
										{error, enoent} -> 
											case IndexFind(user_fs) of
												{error, enoent} -> 
													ems_data_loader:sync(ems_user_loader_db),
													{error, access_denied, enoent};
												{ok, Record} -> {ok, Record}
											end;
										{ok, Record} -> {ok, Record}
									end;
								{ok, Record} -> {ok, Record}
							end;
						{ok, Record} -> {ok, Record}
					end;
				{ok, Record} -> {ok, Record}
			end;
		{ok, Record} -> {ok, Record}
	end.


-spec find_by_email(binary()) -> #user{} | {error, enoent}.
find_by_email(<<>>) -> {error, enoent};	
find_by_email("") -> {error, enoent};	
find_by_email(undefined) -> {error, enoent};	
find_by_email(Email) -> 
	case is_list(Email) of
		true -> EmailStr = string:to_lower(Email);
		false -> EmailStr = string:to_lower(binary_to_list(Email))
	end,
	Ch = string:substr(EmailStr, 1, 1),
	EmailLen = string:len(EmailStr), 
	case ems_util:is_letter_lower(Ch) andalso EmailLen >= 3 of
		true ->
			case string:rchr(EmailStr, $@) > 0 of
				true ->  
					case EmailLen >= 10 of
						true -> find_by_email_(list_to_binary(EmailStr));
						false -> {error, enoent}
					end;
				false -> 
					EmailUnB = list_to_binary(EmailStr ++ "@unb.br"),
					case find_by_email_or_login(EmailUnB, #user.email) of
						{ok, Record} -> {ok, Record};
						{error, enoent} -> 
							case find_by_email_or_login(EmailUnB, #user.login) of
								{ok, Record} -> {ok, Record};
								{error, enoent} -> 
									EmailGmail = list_to_binary(EmailStr ++ "@gmail.com"),
									case find_by_email_or_login(EmailGmail, #user.email) of
										{ok, Record} -> {ok, Record};
										{error, enoent} -> find_by_email_or_login(EmailGmail, #user.login)
									end
							end
					end
			end;
		false -> {error, enoent}
	end.

-spec find_by_email_(binary()) -> #user{} | {error, enoent}.
find_by_email_(EmailBin) -> 
	case mnesia:dirty_index_read(user_db, EmailBin, #user.email) of
		[] -> 
			case mnesia:dirty_index_read(user2_db, EmailBin, #user.email) of
				[] -> 
					case mnesia:dirty_index_read(user_aluno_ativo_db, EmailBin, #user.email) of
						[] -> 
							case mnesia:dirty_index_read(user_aluno_inativo_db, EmailBin, #user.email) of
								[] -> 
									case mnesia:dirty_index_read(user_fs, EmailBin, #user.email) of
										[] -> {error, enoent};
										[Record|_] -> {ok, Record}
									end;
								[Record|_] -> {ok, Record}
							end;
						[Record|_] -> {ok, Record}
					end;
				[Record|_] -> {ok, Record}
			end;
		[Record|_] -> {ok, Record}
	end.

-spec find_by_email_or_login(binary(), non_neg_integer()) -> #user{} | {error, enoent}.
find_by_email_or_login(EmailBin, Where) -> 
	case mnesia:dirty_index_read(user_db, EmailBin, Where) of
		[] -> 
			case mnesia:dirty_index_read(user2_db, EmailBin, Where) of
				[] -> 
					case mnesia:dirty_index_read(user_aluno_ativo_db, EmailBin, Where) of
						[] -> 
							case mnesia:dirty_index_read(user_aluno_inativo_db, EmailBin, Where) of
								[] -> 
									case mnesia:dirty_index_read(user_fs, EmailBin, Where) of
										[] -> {error, enoent};
										[Record|_] -> {ok, Record}
									end;
								[Record|_] -> {ok, Record}
							end;
						[Record|_] -> {ok, Record}
					end;
				[Record|_] -> {ok, Record}	
			end;
		[Record|_] -> {ok, Record}
	end.


-spec find_by_cpf(binary() | string()) -> #user{} | {error, enoent}.
find_by_cpf(<<>>) -> {error, enoent};	
find_by_cpf("") -> {error, enoent};	
find_by_cpf(undefined) -> {error, enoent};	
find_by_cpf(Cpf) ->
	case is_list(Cpf) of
		true -> 
			CpfStr = Cpf,
			CpfBin = list_to_binary(Cpf);
		false ->
			CpfStr = binary_to_list(Cpf),
			CpfBin = Cpf
	end,
	CpfLen = string:len(CpfStr),
	case (CpfLen =:= 11 andalso ems_util:is_cpf_valid(CpfStr)) orelse
		 (CpfLen =:= 14 andalso ems_util:is_cnpj_valid(CpfStr)) of
		true ->
			case mnesia:dirty_index_read(user_db, CpfBin, #user.cpf) of
				[] -> 
					case mnesia:dirty_index_read(user2_db, CpfBin, #user.cpf) of
						[] -> 
							case mnesia:dirty_index_read(user_fs, CpfBin, #user.cpf) of
								[] -> {error, enoent};
								[Record|_] -> {ok, Record}
							end;
						[Record|_] -> {ok, Record}
					end;
				[Record|_] -> {ok, Record}
			end;
		false -> 
			% tenta inserir zeros na frente e refaz a pesquisa
			case CpfLen of
				10 -> Cpf2 = "0" ++ CpfStr;  
				 9 -> Cpf2 = "00" ++ CpfStr;
				 _ -> Cpf2 = CpfStr
			end,
			CpfLen2 = string:len(Cpf2),
			Cpf2Bin = list_to_binary(Cpf2),
			case (CpfLen2 =:= 11 orelse CpfLen2 =:= 14) of  % deve ser CPF ou CNPJ
				true ->
					case mnesia:dirty_index_read(user_db, Cpf2Bin, #user.cpf) of
						[] -> 
							case mnesia:dirty_index_read(user2_db, Cpf2Bin, #user.cpf) of
								[] -> 
									case mnesia:dirty_index_read(user_aluno_ativo_db, Cpf2Bin, #user.cpf) of
										[] -> 
											case mnesia:dirty_index_read(user_aluno_inativo_db, Cpf2Bin, #user.cpf) of
												[] -> 
													case mnesia:dirty_index_read(user_fs, Cpf2Bin, #user.cpf) of
														[] -> {error, enoent};
														[Record|_] -> {ok, Record}
													end;
												[Record|_] -> {ok, Record}
											end;
										[Record|_] -> {ok, Record}
									end;
								[Record|_] -> {ok, Record}	
							end;
						[Record|_] -> {ok, Record}
					end;
				false -> {error, enoent}
			end
	end.

-spec find_by_name(binary() | string()) -> {ok, #user{}} | {error, enoent}.
find_by_name(<<>>) -> {error, enoent};
find_by_name("") -> {error, enoent};
find_by_name(undefined) -> {error, enoent};
find_by_name(Name) when is_list(Name) -> 
	find_by_name(list_to_binary(Name));
find_by_name(Name) -> 
	case ems_db:find_first(?CLIENT_DEFAULT_SCOPE, [{name, "==", Name}]) of
		{ok, Record} -> {ok, Record};
		_ -> {error, enoent}
	end.
	
get_admim_user() ->
	case ems_db:get([user_fs], 1) of
		{ok, Record} -> {ok, Record};
		_ -> {error, enoent}
	end.


-spec to_resource_owner(#user{}, non_neg_integer()) -> binary().
to_resource_owner(undefined, _) -> <<"{}"/utf8>>;
to_resource_owner(User, ClientId) ->
	case User#user.remap_user_id == undefined orelse User#user.remap_user_id == null of
		true -> 
			case User#user.cpf of
				<<>> ->
					{ok, ListaPerfil} = ems_user_perfil:find_by_user_and_client(User#user.id, ClientId, [perfil_id, name]),
					ListaPerfilJson = ems_schema:to_json(ListaPerfil),
					{ok, ListaPermission} = ems_user_permission:find_by_user_and_client(User#user.id, ClientId, [id, perfil_id, name, url, grant_get, grant_post, grant_put, grant_delete, position, glyphicon]),
					ListaPermissionJson = ems_schema:to_json(ListaPermission),
					{ok, ListaPerfilPermission} = ems_user_perfil:find_by_user_and_client_com_permissao(User#user.id, ClientId, [perfil_id, name]),
					ListaPerfilPermissionJson  = ems_schema:to_json(ListaPerfilPermission);
				_ ->
					{ok, ListaPerfil} = ems_user_perfil:find_by_cpf_and_client(User#user.cpf, ClientId, [perfil_id, name]),
					ListaPerfilJson = ems_schema:to_json(ListaPerfil),
					{ok, ListaPermission} = ems_user_permission:find_by_cpf_and_client(User#user.cpf, ClientId, [id, perfil_id, name, url, grant_get, grant_post, grant_put, grant_delete, position, glyphicon]),
					ListaPermissionJson = ems_schema:to_json(ListaPermission),
					{ok, ListaPerfilPermission} = ems_user_perfil:find_by_user_and_client_com_permissao(User#user.id, ClientId, [perfil_id, name]),
					ListaPerfilPermissionJson  = ems_schema:to_json(ListaPerfilPermission)
			end,
			iolist_to_binary([<<"{"/utf8>>,
								<<"\"id\":"/utf8>>, integer_to_binary(User#user.id), <<","/utf8>>,
								<<"\"remap_user_id\":null,"/utf8>>, 
								<<"\"codigo\":"/utf8>>, integer_to_binary(User#user.codigo), <<","/utf8>>,
								<<"\"login\":\""/utf8>>, User#user.login, <<"\","/utf8>>, 
								<<"\"name\":\""/utf8>>, User#user.name, <<"\","/utf8>>,
								<<"\"email\":\""/utf8>>, User#user.email, <<"\","/utf8>>,
								<<"\"type\":"/utf8>>, integer_to_binary(User#user.type), <<","/utf8>>,
								<<"\"subtype\":"/utf8>>, integer_to_binary(User#user.subtype), <<","/utf8>>,
								<<"\"active\":"/utf8>>, ems_util:boolean_to_binary(User#user.active), <<","/utf8>>,
								<<"\"cpf\":\""/utf8>>, User#user.cpf, <<"\","/utf8>>,
								<<"\"lista_perfil\":"/utf8>>, ListaPerfilJson, <<","/utf8>>,
								<<"\"lista_permission\":"/utf8>>, ListaPermissionJson, <<","/utf8>>, 
								<<"\"lista_perfil_permission\":"/utf8>>, ListaPerfilPermissionJson,
							<<"}"/utf8>>]);
		false ->
			io:format("Entrou no false >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> n~n"),
			ListaPerfilFinal = case ems_user_perfil:find_by_user_and_client(User#user.remap_user_id, ClientId, [perfil_id, name]) of
									{ok, ListaPerfil} -> 
										case User#user.cpf of
											<<>> ->
												case ems_user_perfil:find_by_user_and_client(User#user.id, ClientId, [perfil_id, name]) of
													{ok, ListaPerfil2} -> ListaPerfil ++ ListaPerfil2;
													_ -> ListaPerfil
												end;
											_ ->
												case ems_user_perfil:find_by_cpf_and_client(User#user.cpf, ClientId, [perfil_id, name]) of
													{ok, ListaPerfil2} -> ListaPerfil ++ ListaPerfil2;
													_ -> ListaPerfil
												end
										end;
									_ -> 
										case User#user.cpf of
											<<>> ->
												case ems_user_perfil:find_by_user_and_client(User#user.id, ClientId, [perfil_id, name]) of
													{ok, ListaPerfil2} -> ListaPerfil2;
													_ -> []
												end;
											_ ->
												case ems_user_perfil:find_by_cpf_and_client(User#user.cpf, ClientId, [perfil_id, name]) of
													{ok, ListaPerfil2} -> ListaPerfil2;
													_ -> []
												end
										end
								end,
			io:format("Entrou no else no final>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> ~n~n"),
			ListaPerfilJson = ems_schema:to_json(ListaPerfilFinal),
			ListaPermissionFinal = case ems_user_permission:find_by_user_and_client(User#user.remap_user_id, ClientId, [id, perfil_id , name, url, grant_get, grant_post, grant_put, grant_delete, position, glyphicon]) of
										{ok, ListaPermission} ->
											case User#user.cpf of
												<<>> ->
													case ems_user_permission:find_by_user_and_client(User#user.id, ClientId, [id, perfil_id ,name, url, grant_get, grant_post, grant_put, grant_delete, position, glyphicon]) of
														{ok, ListaPermission2} -> ListaPermission ++ ListaPermission2;
														_ -> ListaPermission
													end;
												_ ->
													case ems_user_permission:find_by_cpf_and_client(User#user.cpf, ClientId, [id, perfil_id , name, url, grant_get, grant_post, grant_put, grant_delete, position, glyphicon]) of
														{ok, ListaPermission2} -> ListaPermission ++ ListaPermission2;
														_ -> ListaPermission
													end
											end;
										_ -> 
											case User#user.cpf of
												<<>> ->
													case ems_user_permission:find_by_user_and_client(User#user.id, ClientId, [id, perfil_id , name, url, grant_get, grant_post, grant_put, grant_delete, position, glyphicon]) of
														{ok, ListaPermission2} -> ListaPermission2;
														_ -> []
													end;
												_ ->
													case ems_user_permission:find_by_cpf_and_client(User#user.cpf, ClientId, [id, perfil_id , name, url, grant_get, grant_post, grant_put, grant_delete, position, glyphicon]) of
														{ok, ListaPermission2} -> ListaPermission2;
														_ -> []
													end
											end
									end,
			ListaPermissionJson = ems_schema:to_json(ListaPermissionFinal),

			ListaPerfilPermissionFinal = case ems_user_perfil:find_by_user_and_client(User#user.remap_user_id, ClientId, [id, perfil_id , name, url, grant_get, grant_post, grant_put, grant_delete, position, glyphicon]) of
										{ok, ListaPerfilPermission} ->
											case User#user.cpf of
												<<>> ->
													case ems_user_perfil:find_by_user_and_client_com_permissao(User#user.id, ClientId, [perfil_id, name]) of
														{ok, ListaPerfilPermission2} -> ListaPerfilPermission ++ ListaPerfilPermission2;
														_ -> ListaPerfilPermission
													end;
												_ ->
													case ems_user_perfil:find_by_cpf_and_client_com_permissao(User#user.cpf, ClientId, [id, perfil_id , name, url, grant_get, grant_post, grant_put, grant_delete, position, glyphicon]) of
														{ok, ListaPerfilPermission2} -> ListaPerfilPermission ++ ListaPerfilPermission2;
														_ -> ListaPerfilPermission
													end
											end;
										_ -> 
											case User#user.cpf of
												<<>> ->
													case ems_user_perfil:find_by_user_and_client_com_permissao(User#user.id, ClientId, [id, perfil_id , name, url, grant_get, grant_post, grant_put, grant_delete, position, glyphicon]) of
														{ok, ListaPerfilPermission2} -> ListaPerfilPermission2;
														_ -> []
													end;
												_ ->
													case ems_user_perfil:find_by_cpf_and_client_com_permissao(User#user.cpf, ClientId, [id, perfil_id , name, url, grant_get, grant_post, grant_put, grant_delete, position, glyphicon]) of
														{ok, ListaPerfilPermission2} -> ListaPerfilPermission2;
														_ -> []
													end
											end
									end,
			ListaPerfilPermissionJson = ems_schema:to_json(ListaPerfilPermissionFinal),
			io:format("ListaPerfilPermissionJson >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> ~p~n~n",[ListaPerfilPermissionJson]),
			iolist_to_binary([<<"{"/utf8>>,
								<<"\"id\":"/utf8>>, integer_to_binary(User#user.id), <<","/utf8>>,
								<<"\"remap_user_id\":"/utf8>>, integer_to_binary(User#user.remap_user_id), <<","/utf8>>,
								<<"\"codigo\":"/utf8>>, integer_to_binary(User#user.codigo), <<","/utf8>>,
								<<"\"login\":\""/utf8>>, User#user.login, <<"\","/utf8>>, 
								<<"\"name\":\""/utf8>>, User#user.name, <<"\","/utf8>>,
								<<"\"email\":\""/utf8>>, User#user.email, <<"\","/utf8>>,
								<<"\"type\":"/utf8>>, integer_to_binary(User#user.type), <<","/utf8>>,
								<<"\"subtype\":"/utf8>>, integer_to_binary(User#user.subtype), <<","/utf8>>,
								<<"\"active\":"/utf8>>, ems_util:boolean_to_binary(User#user.active), <<","/utf8>>,
								<<"\"cpf\":\""/utf8>>, User#user.cpf, <<"\","/utf8>>,
								<<"\"lista_perfil\":"/utf8>>, ListaPerfilJson, <<","/utf8>>,
								<<"\"lista_permission\":"/utf8>>, ListaPermissionJson, <<","/utf8>>,
								<<"\"lista_perfil_permission\":"/utf8>>, ListaPerfilPermissionJson,
							<<"}"/utf8>>])
	end.


-spec to_resource_owner(#user{}) -> binary().
to_resource_owner(undefined) -> <<"{}"/utf8>>;
to_resource_owner(User) ->
	case User#user.remap_user_id == undefined orelse User#user.remap_user_id == null of
		true -> 
			iolist_to_binary([<<"{"/utf8>>,
								<<"\"id\":"/utf8>>, integer_to_binary(User#user.id), <<","/utf8>>,
								<<"\"remap_user_id\":null,"/utf8>>, 
								<<"\"codigo\":"/utf8>>, integer_to_binary(User#user.codigo), <<","/utf8>>,
								<<"\"login\":\""/utf8>>, User#user.login, <<"\","/utf8>>, 
								<<"\"name\":\""/utf8>>, User#user.name, <<"\","/utf8>>,
								<<"\"email\":\""/utf8>>, User#user.email, <<"\","/utf8>>,
								<<"\"type\":"/utf8>>, integer_to_binary(User#user.type), <<","/utf8>>,
								<<"\"subtype\":"/utf8>>, integer_to_binary(User#user.subtype), <<","/utf8>>,
								<<"\"active\":"/utf8>>, ems_util:boolean_to_binary(User#user.active), <<","/utf8>>,
								<<"\"cpf\":\""/utf8>>, User#user.cpf, <<"\","/utf8>>,
								<<"\"lista_perfil\":{},"/utf8>>, 
								<<"\"lista_permission\":{}"/utf8>>, 
								<<"\"lista_perfil_permission\":{}"/utf8>>,
							<<"}"/utf8>>]);
		false ->
			iolist_to_binary([<<"{"/utf8>>,
								<<"\"id\":"/utf8>>, integer_to_binary(User#user.id), <<","/utf8>>,
								<<"\"remap_user_id\":"/utf8>>, integer_to_binary(User#user.remap_user_id), <<","/utf8>>,
								<<"\"codigo\":"/utf8>>, integer_to_binary(User#user.codigo), <<","/utf8>>,
								<<"\"login\":\""/utf8>>, User#user.login, <<"\","/utf8>>, 
								<<"\"name\":\""/utf8>>, User#user.name, <<"\","/utf8>>,
								<<"\"email\":\""/utf8>>, User#user.email, <<"\","/utf8>>,
								<<"\"type\":"/utf8>>, integer_to_binary(User#user.type), <<","/utf8>>,
								<<"\"subtype\":"/utf8>>, integer_to_binary(User#user.subtype), <<","/utf8>>,
								<<"\"active\":"/utf8>>, ems_util:boolean_to_binary(User#user.active), <<","/utf8>>,
								<<"\"cpf\":\""/utf8>>, User#user.cpf, <<"\","/utf8>>,
								<<"\"lista_perfil\":{},"/utf8>>, 
								<<"\"lista_permission\":{}"/utf8>>, 
								<<"\"lista_perfil_permission\":{}"/utf8>>,
							<<"}"/utf8>>])
	end.


-spec new_from_map(map(), #config{}) -> {ok, #user{}} | {error, atom()}.
new_from_map(Map, Conf) ->
	try
		put(parse_step, login),
		Login = list_to_binary(string:to_lower(binary_to_list(?UTF8_STRING(maps:get(<<"login">>, Map))))),

		put(parse_step, id),
		Id = maps:get(<<"id">>, Map),
		
		put(parse_step, codigo),
		Codigo = maps:get(<<"codigo">>, Map, 0),
		
		put(parse_step, name),
		Name = ?UTF8_STRING(maps:get(<<"name">>, Map, Login)),
		
		put(parse_step, password),
		Password = maps:get(<<"password">>, Map, <<>>),

		put(parse_step, passwd_crypto),
		PasswdCrypto0 = list_to_binary(string:to_upper(binary_to_list(maps:get(<<"passwd_crypto">>, Map, <<>>)))),
		case PasswdCrypto0 of
						<<"SHA1">> -> 
							PasswdCrypto = PasswdCrypto0,
							Password2 = ?UTF8_STRING(Password);
						<<"MD5">> -> 
							PasswdCrypto = PasswdCrypto0,
							Password2 =	?UTF8_STRING(Password);
						<<"BLOWFISH">> -> 
							PasswdCrypto = PasswdCrypto0,
							Password2 = ?UTF8_STRING(Password);
						_ -> 
							PasswdCrypto = <<"SHA1">>,
							Password2 = ems_util:criptografia_sha1(string:to_lower(binary_to_list(?UTF8_STRING(Password))))
					end,

		put(parse_step, cpf),
		Cpf0 = binary_to_list(?UTF8_STRING(maps:get(<<"cpf">>, Map, <<>>))),
		% O Cpf pode não ter zeros na frente, deve colocar zeros se necessário e validar
		CpfLen = string:len(Cpf0),
		case CpfLen =:= 0 orelse ((CpfLen =:= 11 andalso ems_util:is_cpf_valid(Cpf0)) orelse
								  (CpfLen =:= 14 andalso ems_util:is_cnpj_valid(Cpf0))
								 ) of
			true -> 
				Cpf = list_to_binary(Cpf0);
			false ->
				% tenta inserir zeros na frente e valida novamente
				case CpfLen of
					10 -> Cpf1 = "0" ++ Cpf0;  
					 9 -> Cpf1 = "00" ++ Cpf0;
					 _ -> Cpf1 = Cpf0
				end,
				CpfLen2 = string:len(Cpf1),
				case (CpfLen2 =:= 11 andalso ems_util:is_cpf_valid(Cpf1)) orelse
					 (CpfLen2 =:= 14 andalso ems_util:is_cnpj_valid(Cpf1)) of
					true -> 
						Cpf = list_to_binary(Cpf1);
					false -> 
						% Cpf inválido não é armazenado no barramento. 
						Cpf = <<>>
				end
		end,
		
		% Se não tem CPF mas o login é um CPF válido, atribui ao campo CPF
		case Cpf == <<>> andalso ems_util:is_cpf_valid(Login) of
			true -> Cpf2 = Login;
			false -> Cpf2 = Cpf
		end,
		
		put(parse_step, dt_expire_password),
		DtExpirePassword = case ems_util:date_to_binary(maps:get(<<"dt_expire_password">>, Map, <<>>)) of
							  <<>> -> undefined;
							  DtExpirePasswordValue -> DtExpirePasswordValue
						   end,
		
		put(parse_step, endereco),
		Endereco = ?UTF8_STRING(maps:get(<<"endereco">>, Map, <<>>)),
		
		put(parse_step, complemento_endereco),
		ComplementoEndereco = ?UTF8_STRING(maps:get(<<"complemento_endereco">>, Map, <<>>)),
		
		put(parse_step, bairro),
		Bairro = ?UTF8_STRING(maps:get(<<"bairro">>, Map, <<>>)),
		
		put(parse_step, cidade),
		Cidade = ?UTF8_STRING(maps:get(<<"cidade">>, Map, <<>>)),
		
		put(parse_step, uf),
		Uf = ?UTF8_STRING(maps:get(<<"uf">>, Map, <<>>)),
		
		put(parse_step, cep),
		Cep = ?UTF8_STRING(maps:get(<<"cep">>, Map, <<>>)),
		
		put(parse_step, rg),
		Rg = ?UTF8_STRING(maps:get(<<"rg">>, Map, <<>>)),
		
		put(parse_step, data_nascimento),
		DataNascimento = case ems_util:date_to_binary(maps:get(<<"data_nascimento">>, Map, <<>>)) of
							  <<>> -> undefined;
							  DtNascimentoValue -> DtNascimentoValue
						 end,
		
		put(parse_step, sexo),
		Sexo = case maps:get(<<"sexo">>, Map, undefined) of
					SexoValue when is_binary(SexoValue) -> ems_util:list_to_integer_def(string:strip(binary_to_list(SexoValue)), undefined);
					SexoValue when is_list(SexoValue) -> ems_util:list_to_integer_def(string:strip(SexoValue), undefined);
					SexoValue when is_integer(SexoValue) -> SexoValue;
					undefined -> undefined
				end,
		
		put(parse_step, telefone),
		Telefone = ?UTF8_STRING(maps:get(<<"telefone">>, Map, <<>>)),
		
		put(parse_step, celular),
		Celular = ?UTF8_STRING(maps:get(<<"celular">>, Map, <<>>)),
		
		put(parse_step, ddd),
		DDD = ?UTF8_STRING(maps:get(<<"ddd">>, Map, <<>>)),
		
		put(parse_step, nome_pai),
		NomePai = ?UTF8_STRING(maps:get(<<"nome_pai">>, Map, <<>>)),
		
		put(parse_step, nome_mae),
		NomeMae = ?UTF8_STRING(maps:get(<<"nome_mae">>, Map, <<>>)),
		
		put(parse_step, nacionalidade),
		Nacionalidade = case maps:get(<<"nacionalidade">>, Map, undefined) of
							NacionalidadeValue when is_binary(NacionalidadeValue) -> ems_util:binary_to_integer_def(NacionalidadeValue, undefined);
							NacionalidadeValue when is_integer(NacionalidadeValue) -> NacionalidadeValue;
							undefined -> undefined
						end,
						
		put(parse_step, email),						
		Email0 = ?UTF8_STRING(maps:get(<<"email">>, Map, <<>>)),

		% Se não tem e-mail mas o login é um e-mail válido, atribui ao campo email
		case Email0 == <<>> andalso ems_util:is_email_valido(Login) of
			true -> Email = Login;
			false -> Email = Email0
		end,

		
		put(parse_step, type),
		Type = maps:get(<<"type">>, Map, 1),
		
		put(parse_step, subtype),
		Subtype = maps:get(<<"subtype">>, Map, 0),
		
		put(parse_step, active),
		Active = ems_util:value_to_boolean(maps:get(<<"active">>, Map, true)),
		
		put(parse_step, remap_user_id),
		RemapUserId = maps:get(<<"remap_user_id">>, Map, undefined),
		
		put(parse_step, admin),
		Admin = ems_util:value_to_boolean(maps:get(<<"admin">>, Map, lists:member(Login, Conf#config.cat_restricted_services_admin))),
		
		put(parse_step, ctrl_path),
		CtrlPath = maps:get(<<"ctrl_path">>, Map, <<>>),
		
		put(parse_step, ctrl_file),
		CtrlFile = maps:get(<<"ctrl_file">>, Map, <<>>),
		
		put(parse_step, ctrl_modified),
		CtrlModified = case ems_util:timestamp_binary(maps:get(<<"ctrl_modified">>, Map, <<>>)) of
							  <<>> -> undefined;
							  CtrlModifiedValue -> CtrlModifiedValue
					   end,
		
		put(parse_step, ctrl_hash),
		CtrlHash = erlang:phash2(Map),
		
		put(parse_step, new_user),
		{ok, #user{	id = Id,
					codigo = Codigo,
					login = Login,
					name = Name,
					cpf = Cpf2,
					password = Password2,
					passwd_crypto = PasswdCrypto,
					dt_expire_password = DtExpirePassword,
					endereco = Endereco,
					complemento_endereco = ComplementoEndereco,
					bairro = Bairro,
					cidade = Cidade,
					uf = Uf,
					cep = Cep,
					rg = Rg,
					data_nascimento = DataNascimento,
					sexo = Sexo,
					telefone = Telefone,
					celular = Celular,
					ddd = DDD,
					nome_pai = NomePai,
					nome_mae = NomeMae,
					nacionalidade = Nacionalidade,
					email = Email,
					type_email = 1,
					type = Type,
					subtype = Subtype,
					active = Active,
					remap_user_id = RemapUserId,
					admin = Admin,
					old_login = undefined,
					old_name = undefined,
					old_cpf = undefined,
					old_email = undefined,
					old_password = undefined,
					ctrl_path = CtrlPath,
					ctrl_file = CtrlFile,
					ctrl_modified = CtrlModified,
					ctrl_hash = CtrlHash,
					ctrl_last_login = undefined,
					ctrl_login_count = 0,
					ctrl_last_login_scope = undefined,
					ctrl_last_login_client = undefined
			}
		}
	catch
		_Exception:Reason -> 
			ems_db:inc_counter(edata_loader_invalid_user),
			ems_logger:warn("ems_user parse invalid user specification on field ~p. Reason: ~p\n\t~p.\n", [get(parse_step), Reason, Map]),
			{error, Reason}
	end.


-spec get_table(user_db | user_fs | user_aluno_ativo_db | user_aluno_inativo_db) -> user_db | user_fs | user_aluno_ativo_db | user_aluno_inativo_db.
get_table(SourceType) -> SourceType.

-spec find(user_fs | user_db, non_neg_integer()) -> {ok, #user{}} | {error, enoent}.
find(Table, Id) ->
	case mnesia:dirty_read(Table, Id) of
		[] -> {error, enoent};
		[Record|_] -> {ok, Record}
	end.

-spec exist(user_fs | user_db, non_neg_integer()) -> boolean().
exist(Table, Id) ->
	case mnesia:dirty_read(Table, Id) of
		[] -> false;
		_ -> true
	end.

-spec all(user_fs | user_db) -> list() | {error, atom()}.
all(Table) -> ems_db:all(Table).
	

-spec add_history(#request{}) -> ok.
add_history(Request = #request{user = User, client = Client, service = Service}) ->
	add_history(case User of
					undefined -> #user{};
					public -> #user{name = <<"public">>, 
									login = <<"public">>};
					_ -> User
				end,
				case Client of 
						undefined -> #client{};
						public -> #client{name = <<"public">>};
						_ -> Client
				end,
				case Service of
						undefined -> #service{};
						_ -> Service
				end, 
				Request).


-spec add_history(#user{}, #service{}, #request{}) -> ok.
add_history(User, Service, Request) ->
	add_history(User, #client{}, Service, Request).

-spec add_history(#user{}, #client{}, #service{}, #request{}) -> ok.
add_history(#user{id = UserId,
				  codigo = UserCodigo,
				  login = UserLogin,
				  name = UserName,
				  cpf = UserCpf,
				  email = UserEmail,
				  type = UserType,
				  subtype = UserSubtype,
				  type_email = UserTypeEmail,
				  active = UserActive,
				  admin = UserAdmin},
			#client{id = ClientId,
					name = ClientName},
			#service{rowid = ServiceRowid,
					 name = ServiceName,
				     url = ServiceUrl,
					 type  = ServiceType,
					 service = ServiceService,
					 use_re = ServiceUseRE,
					 public = ServicePublic,
					 version = ServiceVersion,
					 owner = ServiceOwner,
					 group = ServiceGroup,
					 async = ServiceAsync,
					 log_show_payload = LogShowPayload},
			#request{
					   rid = RequestRid,
					   timestamp = RequestTimestamp,
					   %latency = RequestLatency,
					   code  = RequestCode,
					   reason = RequestReason,
					   reason_detail = RequestReasonDetail,
					   operation = RequestOperation,
					   type = RequestType,
					   uri = RequestUri,
					   url = RequestUrl,
					   url_masked = RequestUrlMasked,
					   version = RequestHttpVersion,
					   payload = RequestPayload,
					   querystring = RequestQuerystring,
					   params_url = RequestParamsUrl,
					   content_type_in = RequestContentTypeIn,
					   content_type_out = RequestContentTypeOut,
					   content_length = RequestContentLength,
					   accept = RequestAccept,
					   user_agent = RequestUserAgent,
					   user_agent_version = RequestUserAgentVersion,
					   t1 = RequestT1,
					   authorization = RequestAuthorization,
					   protocol = RequestProtocol,
					   port = RequestPort,
					   %response_data = RequestResponseData,
					   req_hash = RequestReqHash,
					   host = RequestHost,
					   filename = RequestFilename,
					   referer = RequestReferer,
					   access_token = RequestAccessToken}) ->
	try
		RequestTimestamp2 =	case is_binary(RequestTimestamp) of
								true -> RequestTimestamp;
								false -> ems_util:timestamp_binary(RequestTimestamp)
							end,	
		[RequestDate, RequestTime] = string:tokens(binary_to_list(RequestTimestamp2), " "),
		case LogShowPayload of
			true -> 
				case RequestContentLength > 1024 of
					true ->
						case is_binary(RequestPayload) of
							true -> RequestPayload2 = binary:part(RequestPayload, 1, 1024);
							false -> RequestPayload2 = <<>>
						end;
					false -> RequestPayload2 = RequestPayload
				end,
				case is_binary(RequestPayload2) of
					true -> RequestPayload3 = RequestPayload;
					false -> RequestPayload3 = ems_schema:to_json_def(RequestPayload2, <<>>)
				end;
			false -> RequestPayload3 = <<>> 
		end,
		RequestParamsUrl2 = ems_schema:to_json_def(RequestParamsUrl, <<>>),
		UserHistory = #user_history{
						   %% dados do usuário
						   user_id = UserId,
						   user_codigo = UserCodigo,
						   user_login = UserLogin,
						   user_name = UserName,
						   user_cpf = UserCpf,
						   user_email = UserEmail,
						   user_type = UserType,
						   user_subtype = UserSubtype,
						   user_type_email = UserTypeEmail,
						   user_active = UserActive,
						   user_admin = UserAdmin,
						   
						   % dados do cliente
						   client_id = ClientId,
						   client_name = ClientName,
						   
						   %% dados do serviço
						   service_rowid = ServiceRowid,
						   service_name = ServiceName,
						   service_url = ServiceUrl,
						   service_type  = ServiceType,
						   service_service = ServiceService,
						   service_use_re = ServiceUseRE,
						   service_public = ServicePublic,
						   service_version = ServiceVersion,
						   service_owner = ServiceOwner,
						   service_group = ServiceGroup,
						   service_async = ServiceAsync,
						   
						   %% dados da requisição
						   request_rid = RequestRid,
						   request_date = RequestDate,
						   request_time = RequestTime,
						   %request_latency = RequestLatency,
						   request_code  = RequestCode,
						   request_reason = RequestReason,
						   request_reason_detail = RequestReasonDetail,
						   request_operation = RequestOperation,
						   request_type = RequestType,
						   request_uri = RequestUri,
						   request_url = RequestUrl,
						   request_url_masked = RequestUrlMasked,
						   request_http_version = RequestHttpVersion,
						   request_payload = RequestPayload3,
						   request_querystring = RequestQuerystring,
						   request_params_url = RequestParamsUrl2,
						   request_content_type_in = RequestContentTypeIn,
						   request_content_type_out = RequestContentTypeOut,
						   request_content_length = RequestContentLength,
						   request_accept = RequestAccept,
						   request_user_agent = RequestUserAgent,
						   request_user_agent_version = RequestUserAgentVersion,
						   request_t1 = RequestT1,
						   request_authorization = RequestAuthorization,
						   request_protocol = RequestProtocol,
						   request_port = RequestPort,
						   %request_response_data = RequestResponseData,
						   request_bash = RequestReqHash,
						   request_host = RequestHost,
						   request_filename = RequestFilename,
						   request_referer = RequestReferer,
						   request_access_token = RequestAccessToken
					},
		ems_db:insert(UserHistory),
		ok
	catch
		_:Reason ->
			ems_logger:format_error("ems_user add_history failed. Reason ~p.", [Reason]),
			ok
	end.

