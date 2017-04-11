-module(oauth2ems_recurso).

-export([execute/1]).

-include("../include/ems_schema.hrl").

% teste de token de acesso
execute(Request) -> 
	Token = maps:get(<<"token">>, Request#request.querystring_map, []),
	% valida o token recebido
	Result = oauth2:verify_access_token(Token, []),
	case Result of
		{ok,{_,Auth}} -> 	{ok, Request#request{code = 200,  response_data = ems_schema:prop_list_to_json(Auth)} };
		Error -> {ok, Request#request{code = 401,  response_data = ems_schema:to_json(Error)}}
	end.
		
