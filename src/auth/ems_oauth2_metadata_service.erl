-module(ems_oauth2_metadata_service).
-export([execute/1]).

-include("../include/ems_config.hrl").
-include("../include/ems_schema.hrl").

execute(Request = #request{host = Host}) ->
    % Obtém configuração do ems-bus
    Conf = ems_config:getConfig(),
    
    % Tenta obter a URL de autorização configurada (ex: https://servicos.desenv.unb.br/authorize)
    AuthUrl0 = Conf#config.rest_auth_url,
    
    % Lógica de fallback: se não configurado, usa o host da requisição (comportamento antigo)
    AuthUrl = case AuthUrl0 of
        <<>> -> iolist_to_binary([<<"https://">>, Host, <<"/authorize">>]);
        undefined -> iolist_to_binary([<<"https://">>, Host, <<"/authorize">>]);
        _ -> AuthUrl0
    end,
    
    % Deduz o Issuer removendo o sufixo /authorize (RFC 8414 recomenda que issuer seja a base)
    % Ex: https://servicos.desenv.unb.br/authorize -> https://servicos.desenv.unb.br
    Issuer = binary:replace(AuthUrl, <<"/authorize">>, <<>>),
    
    % Obtém scopes configurados no emsbus.conf (estão em formato de lista de atoms)
    AuthDefaultScopes = Conf#config.auth_default_scope,
    
    % Converte lista de atoms para lista de binários
    ScopesSupported = ems_util:atomlist_to_binlist(AuthDefaultScopes),

    % Metadata JSON conforme RFC 8414
    Metadata = #{
        <<"issuer">> => Issuer,
        <<"authorization_endpoint">> => AuthUrl,
        <<"token_endpoint">> => AuthUrl,
        <<"grant_types_supported">> => [
            <<"authorization_code">>,
            <<"client_credentials">>,
            <<"password">>,
            <<"refresh_token">>
        ],
        <<"response_types_supported">> => [<<"code">>, <<"token">>],
        <<"token_endpoint_auth_methods_supported">> => [<<"client_secret_basic">>],
        <<"scopes_supported">> => ScopesSupported
    },
    
    % Retorna JSON
    ResponseData = ems_util:json_encode(Metadata),
    Request2 = Request#request{
        code = 200,
        reason = ok,
        response_data = ResponseData,
        content_type_out = ?CONTENT_TYPE_JSON
    },
    {ok, Request2}.
