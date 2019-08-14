%%********************************************************************
%% @title Module ems_user_perfil
%% @version 1.0.0
%% @doc user_perfil class
%% @author Everton de Vargas Agilar <evertonagilar@gmail.com>
%% @copyright ErlangMS Team
%%********************************************************************

-module(ems_user_perfil).

-include("include/ems_config.hrl").
-include("include/ems_schema.hrl").
-include_lib("stdlib/include/qlc.hrl").

-export([all/0, 
		 find_by_id/1,		 
		 find_by_user_and_client/3,
		 find_by_user_and_client_com_permissao/3,
		 find_by_cpf_and_client_com_permissao/3,
		 find_by_cpf_and_client_com_perfil_permission/3,
		 find_by_id_and_client_com_perfil_permission/3,
		 find_by_cpf_and_client/3,
		 find_by_user/2,
		 find_by_name/1, 
 		 new_from_map/2,
		 get_table/1,
		 find/2,
		 all/1]).


-spec find_by_id(non_neg_integer()) -> {ok, #user_perfil{}} | {error, enoent}.
find_by_id(Id) -> 
	case ems_db:get([user_perfil_db, user_perfil_fs], Id) of
		{ok, Record} -> {ok, Record};
		_ -> {error, enoent}
	end.

-spec all() -> {ok, list()}.
all() -> 
	{ok, ListaUserDb} = ems_db:all(user_perfil_db),
	{ok, ListaUserFs} = ems_db:all(user_perfil_fs),
	{ok, ListaUserDb ++ ListaUserFs}.


-spec find_by_user(non_neg_integer(), list()) -> {ok, list(#user_perfil{})} | {error, enoent}.
find_by_user(Id, Fields) -> 
	case ems_db:find([user_perfil_db, user_perfil_fs], Fields, [{user_id, "==", Id}]) of
		{ok, Records} -> {ok, Records};
		_ -> {error, enoent}
	end.


find_by_cpf_and_client(<<>>, _, _) -> {ok, []};
find_by_cpf_and_client(undefined, _, _) -> {ok, []};
find_by_cpf_and_client(Cpf, ClientId, Fields) -> 
	case ems_client:find_by_id(ClientId) of
		{ok, Client} ->
			case ems_db:find(Client#client.scope, [id, remap_user_id], [{cpf, "==", Cpf}]) of
				{ok, ListIdsUserByCpfMap} -> 
					find_by_cpf_and_client_(ListIdsUserByCpfMap, ClientId, Fields, []);
				_ -> 
					{ok, []}
			end;
		{error, enoent} -> {ok, []}
	end.

find_by_cpf_and_client_([], _, _, Result) -> 
	{ok, Result};
find_by_cpf_and_client_([UserByCpfMap|T], ClientId, Fields, Result) ->
	UserId = maps:get(<<"id">>, UserByCpfMap),
	RemapUserId = maps:get(<<"remap_user_id">>, UserByCpfMap),
	case find_by_user_and_client(UserId, ClientId, Fields) of
		{ok, Records} -> 
			Result2 = Result ++ Records;
		_ -> Result2 = Result
	end,
	case RemapUserId  of
		null -> Result3 = Result2;
		undefined -> Result3 = Result2;
		_ ->
			case ems_db:find([user_perfil_db, user_perfil_fs], Fields, [{user_id, "==", RemapUserId}]) of
				{ok, Records2} -> 
					Result3 = Result2 ++ Records2;
				_ -> Result3 = Result2
			end
	end,
	find_by_cpf_and_client_(T, ClientId, Fields, Result3).
	
	
-spec find_by_user_and_client(non_neg_integer(), non_neg_integer(), list()) -> {ok, list(#user_perfil{})} | {error, enoent}.
find_by_user_and_client(undefined, _, _) -> {ok, []};
find_by_user_and_client(UserId, ClientId, Fields) -> 
	case ems_db:find([user_perfil_db, user_perfil_fs], Fields, [{user_id, "==", UserId}, {client_id, "==", ClientId}]) of
		{ok, Records} ->
			{ok, Records};
		_ -> {ok, []}
	end.


find_by_cpf_and_client_com_perfil_permission(<<>>, _, _) -> {ok, []};
find_by_cpf_and_client_com_perfil_permission(undefined, _, _) -> {ok, []};
find_by_cpf_and_client_com_perfil_permission(User, ClientId, Fields) -> 
	Value = case ems_client:find_by_id(ClientId) of
		{ok, Client} ->
			case ems_db:find(Client#client.scope, [id, remap_user_id, type, cpf, name], [{cpf, "==", User#user.cpf}]) of
				{ok, UserCpfList} ->  
					io:format("UserCpfList >>>>>>>>>>>>>>>>>>>>>>> ~p~n~n",[UserCpfList]),
					find_by_cpf_and_client_com_perfil_permission_aluno_tecnico_(UserCpfList, ClientId, Fields, []);
				{error, enoent} -> {ok, []}
			end;
		{error, enoent} -> {ok, []}
	end,
	{ok, Value}.


find_by_cpf_and_client_com_perfil_permission_aluno_tecnico_([], _, _, Result) ->
	{ok, Result};
find_by_cpf_and_client_com_perfil_permission_aluno_tecnico_([H|T], ClientId, Fields, Result) ->
	case find_by_user_and_client_com_permissao(maps:get(<<"id">>, H), ClientId, Fields) of
		{ok, []} ->
			io:format("Chegou aqui no [] do método principal >>>>>>>>>>>>>>>>>>>>>>>>> ~n~n"),
			Result2 = find_by_client_com_perfil_permission_aluno(H, ClientId, Fields);
		{ok, Records} -> 
			case ems_user_dados_funcionais:find_by_id(maps:get(<<"id">>, H)) of 
				{ok, TypeResolveList} ->
					TypeResolve = ems_util:hd_or_empty(TypeResolveList),
					case maps:get(<<"type">>, TypeResolve) of 
						0 -> Type = interno;
						1 -> Type = tecnico;
						2 -> Type = docente;
						3 -> Type = discente;
						4 -> Type = terceiros;
						_ -> Type = error
					end,		
					ListTypePerfilPermisson = change_user_type_to_atom(Type, Records),
					Result3 = lists:append(Result, [ListTypePerfilPermisson]),
					{ok, ValueAluno} = find_by_client_com_perfil_permission_aluno(H, ClientId, Fields),
					case ValueAluno of 
						[] ->
							Result2 = Result3;
						_ ->
							Result2 = lists:append(Result3, [ValueAluno])
					end;

			{error, enoent} -> 
					{ok, Result2} = find_by_client_com_perfil_permission_aluno(H, ClientId, Fields)
			end;		
		_ ->
			io:format("Chegou aqui no {error, enoent} do método principal >>>>>>>>>>>>>>>>>>>>>>>>> ~n~n"),
			Result2 = lists:appnd(Result, find_by_client_com_perfil_permission_aluno(H, ClientId, Fields))		
	end,
	find_by_cpf_and_client_com_perfil_permission_aluno_tecnico_(T, ClientId, Fields, Result ++ Result2).


find_by_client_com_perfil_permission_aluno(User, ClientId, Fields) ->
	case ems_db:find([user_aluno_ativo_db, user_aluno_inativo_db], [id, name, remap_user_id, type], [{cpf, "==", maps:get(<<"cpf">>, User)}]) of 
		{ok,[]} -> 
			{ok,[]};
		{ok, UserAlunoList} -> 			
				UserAluno = ems_util:hd_or_empty(UserAlunoList),
				{ok, UserAlunoById} = ems_db:find_by_id([user_aluno_ativo_db, user_aluno_inativo_db], maps:get(<<"id">>, UserAluno)),
				case find_by_user_and_client_com_permissao(UserAlunoById#user.remap_user_id, ClientId, Fields) of
					{ok,[]} -> 
						{ok, #{}};
					{ok, RecordsAluno} -> 
						AlunosRecordsMap = ems_util:hd_or_empty(RecordsAluno),		
						ListTypePerfilPermissonAluno = change_user_type_to_atom(maps:get(<<"type">>, UserAluno), AlunosRecordsMap),
						{ok , ListTypePerfilPermissonAluno};
					_ -> 
						{ok, #{}}
				end;
		_ -> {ok, #{}}
	end.


find_by_id_and_client_com_perfil_permission(User, ClientId, Fields) ->	
	case ems_db:find([user_aluno_ativo_db, user_aluno_inativo_db], [id, name, remap_user_id], [{cpf, "==", User#user.cpf}]) of 
		{ok, []} -> 
			{ok, #{}};
		{ok, UserAluno} -> 

				case find_by_user_and_client_com_permissao(UserAluno#user.remap_user_id, ClientId, Fields) of
					{ok, []} -> 
							{ok, []};
					{ok, RecordsAluno} -> 
						AlunosRecordsMap = ems_util:hd_or_empty(RecordsAluno),
						ListTypePerfilPermissonAluno = change_user_type_to_atom(UserAluno#user.type, AlunosRecordsMap),
						{ok , ListTypePerfilPermissonAluno};
					_ -> {ok, #{}}
				end;
		_ -> {ok, #{}}
	end.


change_user_type_to_atom(UserType, RecordsAluno) ->
	case UserType of 
		interno -> #{interno => RecordsAluno};
		tecnico -> #{tecnico => RecordsAluno};
		docente -> #{docente => RecordsAluno};
		discente -> #{discente => RecordsAluno};
		terceiros -> #{terceiros => RecordsAluno}
	end.

-spec find_by_user_and_client_com_permissao(non_neg_integer(), non_neg_integer(), list()) -> list(map()).
find_by_user_and_client_com_permissao(undefined, _, _) ->
 	{ok, []};
find_by_user_and_client_com_permissao(UserId, ClientId, Fields) -> 
	case find_by_user_and_client(UserId, ClientId, Fields) of
		{ok,[]} ->
			{ok,[]};
		{ok, ListaPerfil} ->
			find_by_user_and_client_com_permissao_(ListaPerfil, UserId, ClientId, []);
		_ -> {ok,[]}	
	end.

find_by_user_and_client_com_permissao_([], _, _, Result) ->
	{ok, Result};
find_by_user_and_client_com_permissao_([H|T], UserId, ClientId, Result) -> 
	PerfilId = maps:get(<<"perfil_id">>, H, <<>>),
	case ems_db:find([user_permission_db, user_permission_fs], [id, perfil_id, name, url, grant_get, grant_post, grant_put, grant_delete, position, glyphicon], [{ client_id, "==", ClientId}, { perfil_id, "==", PerfilId}, {user_id, "==", UserId} ]) of
		{ok, ListaPermissao} ->
			PerfilPermissao = add_permission_in_perfil(H,ListaPermissao),
			Item = #{perfil => PerfilPermissao},
			Result2 =  [Item | Result],
			find_by_user_and_client_com_permissao_(T, UserId, ClientId, Result2);
		_ ->
			find_by_user_and_client_com_permissao_(T, UserId, ClientId, Result)
	end.
	
add_permission_in_perfil(Perfil, ListaPermissao) ->
	 maps:put(<<"permissoes">>,ListaPermissao, Perfil).
	 


find_by_cpf_and_client_com_permissao(<<>>, _, _) -> {ok, []};
find_by_cpf_and_client_com_permissao(undefined, _, _) -> {ok, []};
find_by_cpf_and_client_com_permissao(Cpf, ClientId, Fields) -> 
	case ems_client:find_by_id(ClientId) of
		{ok, Client} ->
			case ems_db:find(Client#client.scope, [id, remap_user_id], [{cpf, "==", Cpf}]) of
				{ok, ListIdsUserByCpfMap} -> 
					find_by_cpf_and_client_com_permissao_(ListIdsUserByCpfMap, ClientId, Fields, []);
				_ -> 
					{ok, []}
			end;
		{error, enoent} -> {ok, []}
	end.

find_by_cpf_and_client_com_permissao_([], _, _, Result) -> {ok, Result};
find_by_cpf_and_client_com_permissao_([UserByCpfMap|T], ClientId, Fields, Result) ->
	UserId = maps:get(<<"id">>, UserByCpfMap),
	RemapUserId = maps:get(<<"remap_user_id">>, UserByCpfMap),
	case find_by_user_and_client_com_permissao(UserId, ClientId, Fields) of
		{ok, Records} -> 
			Result2 = Result ++ Records;
		_ -> Result2 = Result
	end,
	case RemapUserId  of
		null -> Result3 = Result2;
		undefined -> Result3 = Result2;
		_ ->
			case find_by_user_and_client_com_permissao(RemapUserId, ClientId, Fields) of
				{ok, Records2} -> 
					Result3 = Result2 ++ Records2;
				_ -> Result3 = Result2
			end
	end,
	find_by_cpf_and_client_com_permissao_(T, ClientId, Fields, Result3).
	


-spec find_by_name(binary() | string()) -> {ok, #user_perfil{}} | {error, enoent}.
find_by_name(<<>>) -> {error, enoent};
find_by_name("") -> {error, enoent};
find_by_name(undefined) -> {error, enoent};
find_by_name(Name) when is_list(Name) -> 
	find_by_name(list_to_binary(Name));
find_by_name(Name) -> 
	case ems_db:find_first(user_perfil_db, [{name, "==", Name}]) of
		{error, enoent} ->
			case ems_db:find_first(user_perfil_fs, [{name, "==", Name}]) of
				{error, enoent} -> {error, enoent};
				{ok, Record2} -> {ok, Record2}
			end;
		{ok, Record} -> {ok, Record}
	end.


-spec new_from_map(map(), #config{}) -> {ok, #user_perfil{}} | {error, atom()}.
new_from_map(Map, _Conf) ->
	try
	
		put(parse_step, id),
		Id = ems_util:parse_to_integer(maps:get(<<"id">>, Map)),
	
		put(parse_step, perfil_id),
		PerfilId = ems_util:parse_to_integer(maps:get(<<"perfil_id">>, Map, Id)),
	
		put(parse_step, user_id),
		UserId = ems_util:parse_to_integer(maps:get(<<"user_id">>, Map)),
	
		put(parse_step, client_id),
		ClientId = ems_util:parse_to_integer(maps:get(<<"client_id">>, Map, undefined)),
	
		put(parse_step, name),
		Name = ?UTF8_STRING(maps:get(<<"name">>, Map)),
	
		put(parse_step, ctrl_path),
		CtrlPath = maps:get(<<"ctrl_path">>, Map, <<>>),

		put(parse_step, ctrl_file),
		CtrlFile = maps:get(<<"ctrl_file">>, Map, <<>>),

		put(parse_step, ctrl_modified),
		CtrlModified = maps:get(<<"ctrl_modified">>, Map, undefined),

		put(parse_step, ctrl_hash),
		CtrlHash = erlang:phash2(Map),
	
		{ok, #user_perfil{id = Id,
						  perfil_id = PerfilId,
						  user_id = UserId,
						  client_id = ClientId,
						  name = Name,
						  ctrl_path = CtrlPath,
						  ctrl_file = CtrlFile,
						  ctrl_modified = CtrlModified,
						  ctrl_hash = CtrlHash
			}
		}
	catch
		_Exception:Reason -> 
			ems_db:inc_counter(edata_loader_invalid_user_perfil),
			ems_logger:warn("ems_user parse invalid user_perfil specification on field ~p: ~p\n\t~p.\n", [get(parse_step), Reason, Map]),
			{error, Reason}
	end.


-spec get_table(fs | db) -> user_perfil_db | user_perfil_fs.
get_table(db) -> user_perfil_db;
get_table(fs) -> user_perfil_fs.

-spec find(user_perfil_fs | user_perfil_db, non_neg_integer()) -> {ok, #user_perfil{}} | {error, enoent}.
find(Table, Id) ->
	case mnesia:dirty_read(Table, Id) of
		[] -> {error, enoent};
		[Record|_] -> {ok, Record}
	end.

-spec all(user_perfil_fs | user_perfil_db) -> list() | {error, atom()}.
all(Table) -> ems_db:all(Table).

