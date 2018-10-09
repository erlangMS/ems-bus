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
	case ems_db:get([user_db, user_aluno_ativo_db, user_aluno_inativo_db, user_fs], Id) of
		{ok, Record} -> {ok, Record};
		_ -> {error, enoent}
	end.

-spec all() -> {ok, list()}.
all() -> 
	{ok, ListaUserDb} = ems_db:all(user_db),
	{ok, ListaUserAlunoAtivoDb} = ems_db:all(user_aluno_ativo_db),
	{ok, ListaUserAlunoInativoDb} = ems_db:all(user_aluno_inativo_db),
	{ok, ListaUserFs} = ems_db:all(user_fs),
	{ok, ListaUserDb ++ ListaUserAlunoAtivoDb ++ ListaUserAlunoInativoDb ++ ListaUserFs}.
	

-spec find_by_filter(list(binary()), tuple()) -> {ok, list(#user{})} | {error, atom(), atom()}.
find_by_filter(Fields, Filter) -> 
	ems_db:find([user_db, user_aluno_ativo_db, user_aluno_inativo_db, user_fs], Fields, Filter).



-spec find_by_codigo_pessoa(non_neg_integer()) -> {ok, list(#user{})} | {error, enoent}.
find_by_codigo_pessoa(Codigo) ->
	case Codigo > 0 of
		true ->
			case mnesia:dirty_index_read(user_db, Codigo, #user.codigo) of
				[] -> case mnesia:dirty_index_read(user_aluno_ativo_db, Codigo, #user.codigo) of
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
		false -> {error, enoent}
	end.


-spec find_by_codigo_pessoa(atom(), non_neg_integer()) -> {ok, list(#user{})} | {error, enoent}.
find_by_codigo_pessoa(Table, Codigo) ->
	case mnesia:dirty_index_read(Table, Codigo, #user.codigo) of
		[] -> {error, enoent};
		Records -> {ok, Records}
	end.


find_index_by_login_and_password([], _LoginBin, _LoginSemBarraBin, _PasswordBin, _PassowrdBinCrypto, _PassowrdBinLowerCrypto, _PassowrdBinUpperCrypto, _PasswordStrLower, _PasswordStrUpper) ->
	{error, access_denied, enoent};
find_index_by_login_and_password([Table|T], LoginBin, LoginSemBarraBin, PasswordBin, PassowrdBinCrypto, PassowrdBinLowerCrypto, PassowrdBinUpperCrypto, PasswordStrLower, PasswordStrUpper) ->
	case mnesia:dirty_index_read(Table, LoginBin, #user.login) of
		[User = #user{password = PasswordUser}|_] -> 
			case PasswordUser =:= PassowrdBinCrypto 
				 orelse PasswordUser =:= PasswordBin 
				 orelse PasswordUser =:= PassowrdBinLowerCrypto 
				 orelse PasswordUser =:= PasswordStrLower 
				 orelse PasswordUser =:= PassowrdBinUpperCrypto 
				 orelse PasswordUser =:= PasswordStrUpper of
					true -> 
						mnesia:dirty_write(Table, User),
						{ok, User};
					false -> 
						find_index_by_login_and_password(T, LoginBin, LoginSemBarraBin, PasswordBin, PassowrdBinCrypto, PassowrdBinLowerCrypto, PassowrdBinUpperCrypto, PasswordStrLower, PasswordStrUpper)
			end;
		_ -> 
			case mnesia:dirty_index_read(Table, LoginSemBarraBin, #user.login) of
				[User = #user{password = PasswordUser}|_] -> 
					case PasswordUser =:= PassowrdBinCrypto 
						 orelse PasswordUser =:= PasswordBin 
						 orelse PasswordUser =:= PassowrdBinLowerCrypto 
						 orelse PasswordUser =:= PasswordStrLower 
						 orelse PasswordUser =:= PassowrdBinUpperCrypto 
						 orelse PasswordUser =:= PasswordStrUpper of
							true -> 
								mnesia:dirty_write(user_cache_lru, User),
								{ok, User};
							false -> 
								find_index_by_login_and_password(T, LoginBin, LoginSemBarraBin, PasswordBin, PassowrdBinCrypto, PassowrdBinLowerCrypto, PassowrdBinUpperCrypto, PasswordStrLower, PasswordStrUpper)
					end;
				_ -> find_index_by_login_and_password(T, LoginBin, LoginSemBarraBin, PasswordBin, PassowrdBinCrypto, PassowrdBinLowerCrypto, PassowrdBinUpperCrypto, PasswordStrLower, PasswordStrUpper)
			end
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
	case PasswordSize >= 4 andalso PasswordSize =< 100 of
		true ->
			LoginStr = case is_list(Login) of
							true -> string:to_lower(Login);
							false -> string:to_lower(binary_to_list(Login))
					   end,
			LoginStrSemBarra = re:replace(LoginStr, "/", "", [{return, list}]),
			LoginBin = list_to_binary(LoginStr),
			LoginSemBarraBin = list_to_binary(LoginStrSemBarra),
			PasswordStrLower = string:to_lower(PasswordStr),
			PasswordStrUpper = string:to_upper(PasswordStr),
			PasswordBin = list_to_binary(PasswordStr),
			PassowrdBinCrypto = ems_util:criptografia_sha1(PasswordStr),
			PassowrdBinLowerCrypto = ems_util:criptografia_sha1(PasswordStrLower),
			PassowrdBinUpperCrypto = ems_util:criptografia_sha1(PasswordStrUpper),
			case Client of
				undefined -> LoadersFind = [user_db, user_aluno_ativo_db, user_aluno_inativo_db, user_fs];
				_ -> LoadersFind = Client#client.scope
			end,
			find_index_by_login_and_password(LoadersFind, 
											 LoginBin, LoginSemBarraBin, PasswordBin, PassowrdBinCrypto, PassowrdBinLowerCrypto, PassowrdBinUpperCrypto, PasswordStrLower, PasswordStrUpper);
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
	LoginStrSemBarra = re:replace(LoginStr, "/", "", [{return, list}]),
	LoginBin = list_to_binary(LoginStr),
	LoginSemBarraBin = list_to_binary(LoginStrSemBarra),
	IndexFind = fun(Table) ->
		case mnesia:dirty_index_read(Table, LoginBin, #user.login) of
			[User|_] -> {ok, User};
			_ -> 
				case mnesia:dirty_index_read(Table, LoginSemBarraBin, #user.login) of
					[User|_] -> {ok, User};
					_ -> {error, enoent}
				end
		end
	end,
	case IndexFind(user_db) of
		{error, enoent} -> 
			case IndexFind(user_aluno_ativo_db) of
				{error, enoent} -> 
					case IndexFind(user_aluno_inativo_db) of
						{error, enoent} -> 
							case IndexFind(user_fs) of
								{error, enoent} -> {error, access_denied, enoent};
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
	end.

-spec find_by_email_or_login(binary(), non_neg_integer()) -> #user{} | {error, enoent}.
find_by_email_or_login(EmailBin, Where) -> 
	case mnesia:dirty_index_read(user_db, EmailBin, Where) of
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
					case mnesia:dirty_index_read(user_fs, CpfBin, #user.cpf) of
						[] -> {error, enoent};
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
	case ems_db:find_first([user_db, user_aluno_ativo_db, user_aluno_inativo_db], [{name, "==", Name}]) of
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
	case User#user.remap_user_id == undefined of
		true -> 
			{ok, ListaPerfil} = ems_user_perfil:find_by_user_and_client(User#user.id, ClientId, [id, name]),
			ListaPerfilJson = ems_schema:to_json(ListaPerfil),
			{ok, ListaPermission} = ems_user_permission:find_by_user_and_client(User#user.id, ClientId, [id, name, url, grant_get, grant_post, grant_put, grant_delete, position, glyphicon]),
			ListaPermissionJson = ems_schema:to_json(ListaPermission),
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
								<<"\"lista_permission\":"/utf8>>, ListaPermissionJson, 
							<<"}"/utf8>>]);
		false ->
			{ok, ListaPerfil} = ems_user_perfil:find_by_user_and_client(User#user.remap_user_id, ClientId, [id, name]),
			ListaPerfilJson = ems_schema:to_json(ListaPerfil),
			{ok, ListaPermission} = ems_user_permission:find_by_user_and_client(User#user.remap_user_id, ClientId, [id, name, url, grant_get, grant_post, grant_put, grant_delete, position, glyphicon]),
			ListaPermissionJson = ems_schema:to_json(ListaPermission),
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
								<<"\"lista_permission\":"/utf8>>, ListaPermissionJson, 
							<<"}"/utf8>>])
	end.


-spec to_resource_owner(#user{}) -> binary().
to_resource_owner(undefined) -> <<"{}"/utf8>>;
to_resource_owner(User) ->
	case User#user.remap_user_id == undefined of
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
							<<"}"/utf8>>])
	end.


-spec new_from_map(map(), #config{}) -> {ok, #user{}} | {error, atom()}.
new_from_map(Map, Conf) ->
	try
		PasswdCrypto = maps:get(<<"passwd_crypto">>, Map, <<>>),
		Password = maps:get(<<"password">>, Map, <<>>),
		Login = list_to_binary(string:to_lower(binary_to_list(?UTF8_STRING(maps:get(<<"login">>, Map))))),
		{ok, #user{	id = maps:get(<<"id">>, Map),
					codigo = maps:get(<<"codigo">>, Map, 0),
					login = Login,
					name = ?UTF8_STRING(maps:get(<<"name">>, Map, Login)),
					cpf = ?UTF8_STRING(maps:get(<<"cpf">>, Map, <<>>)),
					password = case PasswdCrypto of
									<<"SHA1">> -> ?UTF8_STRING(Password);
									_ -> ems_util:criptografia_sha1(string:to_lower(binary_to_list(?UTF8_STRING(Password))))
							   end,
					passwd_crypto = <<"SHA1">>,
					dt_expire_password = case ems_util:date_to_binary(maps:get(<<"dt_expire_password">>, Map, <<>>)) of
											  <<>> -> undefined;
											  DtExpirePasswordValue -> DtExpirePasswordValue
										 end,
					endereco = ?UTF8_STRING(maps:get(<<"endereco">>, Map, <<>>)),
					complemento_endereco = ?UTF8_STRING(maps:get(<<"complemento_endereco">>, Map, <<>>)),
					bairro = ?UTF8_STRING(maps:get(<<"bairro">>, Map, <<>>)),
					cidade = ?UTF8_STRING(maps:get(<<"cidade">>, Map, <<>>)),
					uf = ?UTF8_STRING(maps:get(<<"uf">>, Map, <<>>)),
					cep = ?UTF8_STRING(maps:get(<<"cep">>, Map, <<>>)),
					rg = ?UTF8_STRING(maps:get(<<"rg">>, Map, <<>>)),
					data_nascimento = ems_util:date_to_binary(maps:get(<<"data_nascimento">>, Map, <<>>)),
					sexo = case maps:get(<<"sexo">>, Map, undefined) of
								SexoValue when is_binary(SexoValue) -> ems_util:list_to_integer_def(string:strip(binary_to_list(SexoValue)), undefined);
								SexoValue when is_list(SexoValue) -> ems_util:list_to_integer_def(string:strip(SexoValue), undefined);
								SexoValue when is_integer(SexoValue) -> SexoValue;
								undefined -> undefined
							end,
					telefone = ?UTF8_STRING(maps:get(<<"telefone">>, Map, <<>>)),
					celular = ?UTF8_STRING(maps:get(<<"celular">>, Map, <<>>)),
					ddd = ?UTF8_STRING(maps:get(<<"ddd">>, Map, <<>>)),
					nome_pai = ?UTF8_STRING(maps:get(<<"nome_pai">>, Map, <<>>)),
					nome_mae = ?UTF8_STRING(maps:get(<<"nome_mae">>, Map, <<>>)),
					nacionalidade = case maps:get(<<"nacionalidade">>, Map, undefined) of
										NacionalidadeValue when is_binary(NacionalidadeValue) -> ems_util:binary_to_integer_def(NacionalidadeValue, undefined);
										NacionalidadeValue when is_integer(NacionalidadeValue) -> NacionalidadeValue;
										undefined -> undefined
									end,
					email = ?UTF8_STRING(maps:get(<<"email">>, Map, <<>>)),
					type = maps:get(<<"type">>, Map, 1),
					subtype = maps:get(<<"subtype">>, Map, 0),
					active = ems_util:value_to_boolean(maps:get(<<"active">>, Map, true)),
					remap_user_id = maps:get(<<"remap_user_id">>, Map, undefined),
					admin = ems_util:value_to_boolean(maps:get(<<"admin">>, Map, lists:member(Login, Conf#config.cat_restricted_services_admin))),
					ctrl_path = maps:get(<<"ctrl_path">>, Map, <<>>),
					ctrl_file = maps:get(<<"ctrl_file">>, Map, <<>>),
					ctrl_modified = maps:get(<<"ctrl_modified">>, Map, undefined),
					ctrl_hash = erlang:phash2(Map)
			}
		}
	catch
		_Exception:Reason -> 
			ems_db:inc_counter(edata_loader_invalid_user),
			ems_logger:warn("ems_user parse invalid user specification: ~p\n\t~p.\n", [Reason, Map]),
			{error, Reason}
	end.


-spec get_table(user_db | user_fs | user_aluno_ativo_db | user_aluno_inativo_db) -> user_db | user_fs | user_aluno_ativo_db | user_aluno_inativo_db.
get_table(user_db) -> user_db;
get_table(user_fs) -> user_fs;
get_table(user_aluno_ativo_db) -> user_aluno_ativo_db;
get_table(user_aluno_inativo_db) -> user_aluno_inativo_db.

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
					 async = ServiceAsync},
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
					   %payload = RequestPayload,
					   querystring = RequestQuerystring,
					   %params_url = RequestParamsUrl,
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
	RequestTimestamp2 =	case is_binary(RequestTimestamp) of
							true -> RequestTimestamp;
							false -> ems_util:timestamp_binary(RequestTimestamp)
						end,
	[RequestDate, RequestTime] = string:split(RequestTimestamp2, " "),
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
					   %request_payload = RequestPayload,
					   request_querystring = RequestQuerystring,
					   %request_params_url = RequestParamsUrl,
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
	ok.

