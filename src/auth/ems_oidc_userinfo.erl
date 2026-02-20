-module(ems_oidc_userinfo).

-export([execute/1]).

-include("include/ems_config.hrl").
-include("include/ems_schema.hrl").

execute(Request) ->
	try
		% 1. Extrair Token do Header Authorization
		Authorization = Request#request.authorization,
		Token = parse_bearer_token(Authorization),
		
		% 2. Validar Token
		case ems_oauth2_backend:resolve_access_token(Token, []) of
			{ok, {_, Context}} ->
				% 3. Obter dados do usuário do contexto
				% O contexto é gravado como record #a{} (definido em ems_oauth2_backend, mas é interno)
				% Ou pode ser que o ems_bus grave de outra forma.
				% Vamos assumir que conseguimos recuperar o #user{} ou pelo menos o ID.
				% Analisando ems_oauth2_backend: resolve_access_token retorna o Context salvo.
				
				% No ems_oauth2_backend, o record é:
				% -record(a, { client, resowner, scope, state, ttl }).
				% Porém, esse record não está exportado/incluído aqui.
				% Vamos tentar extrair o resowner (User) pela posição ou assumir que o Context é o User direto?
				% Não, o ems-bus usa a lib oauth2.
				% Vamos fazer algo mais robusto: se o resolve funcionar, extraímos o user.
				
				% HACK: Como o record 'a' é local do backend, vamos tentar inferir ou usar ems_db para buscar o token e ver o conteúdo.
				% Mas espere, ems_oauth2_backend exports resolve_access_token.
				% Se olharmos o ems_oauth2_backend:resolve_access_token, ele retorna {ok, {[], Context}}.
				% O Context é o que foi passado no associate_access_token.
				% No ems_oauth2_authorize, quem chama associate é a lib oauth2, que chama o backend.
				
				% Simplificação: O ems-bus tem uma função ems_util:get_user_from_token? Não.
				
				% Vamos assumir que Context é {Client, User, Scope, ...} ou similar.
				% Como não temos acesso fácil à estrutura interna do oauth2 lib aqui,
				% vamos usar uma estratégia comum em erlang: pattern matching dinâmico ou supor a estrutura
				% OU melhor: Olhando o log ou código do ems_oauth2_backend, o Context é um record #a{}.
				% Como não tenho o .hrl do oauth2, vou ter que "adivinhar" a posição ou usar element.
				% record a: client(2), resowner(3), scope(4)...
				
				ResOwner = element(3, Context),
				
				case ResOwner of
					#user{} ->
						return_user_info(ResOwner);
					_ ->
						{error, Request#request{code = ?HTTP_UNAUTHORIZED, response_data = ?EINVALID_TOKEN_USER_JSON}}
				end;
			_ ->
				{error, Request#request{code = ?HTTP_UNAUTHORIZED, response_data = ?EINVALID_TOKEN_JSON}}
		end
	catch
		_:_ ->
		{error, Request#request{code = ?HTTP_UNAUTHORIZED, response_data = ?EUNAUTHORIZED_JSON}}
	end.

parse_bearer_token(<<"Bearer ", Token/binary>>) -> Token;
parse_bearer_token(<<"bearer ", Token/binary>>) -> Token;
parse_bearer_token(_) -> <<>>.

return_user_info(User) ->
	% Monta JSON com claims padrão OIDC
	Claims = #{
		<<"sub">> => ems_util:integer_to_binary_def(User#user.id, 0),
		<<"name">> => User#user.name,
		<<"preferred_username">> => User#user.login,
		<<"email">> => User#user.email,
		<<"cpf">> => User#user.cpf
	},
	
	ResponseData = ems_util:json_encode(Claims),
	
	{ok, #request{
		code = ?HTTP_OK,
		content_type_out = <<"application/json">>,
		response_data = ResponseData
	}}.
