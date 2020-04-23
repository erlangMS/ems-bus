%%********************************************************************
%% @title http_messages
%% @version 1.0.0
%% @doc Contém definições de mensagens HTTP.
%% @author Everton de Vargas Agilar <evertonagilar@gmail.com>
%% @copyright ErlangMS Team
%%********************************************************************

%% Mensagens de erro 
-define(MSG_SERVICO_NAO_ENCONTRADO, "Serviço ~p não encontrado.").
-define(MSG_SERVICO_NAO_DISP, "Serviço ~p listado no catálogo mas não disponível.").
-define(MSG_SERVICO_FALHOU, "Serviço ~p falhou ao atender solicitação. Motivo: ~p.").


%% Mensagens de erro HTTP no formato JSON
-define(HTTP_ERROR_400, <<"{\"error\":\"400\",\"message\":\"einvalid_request\"}"/utf8>>).
-define(HTTP_ERROR_400(Reason), iolist_to_binary(io_lib:format(<<"{\"error\":~p}"/utf8>>, [Reason]))).
-define(HTTP_ERROR_401, <<"{\"error\":\"HTTP 401\",\"message\":\"enauthorized_access\"}"/utf8>>).
-define(HTTP_ERROR_404, <<"{\"error\":\"HTTP 404\",\"message\":\"enoent\"}"/utf8>>).
-define(HTTP_ERROR_415, <<"{\"error\":\"HTTP 415\",\"message\":\"einvalid_payload\"}"/utf8>>).
-define(HTTP_ERROR_502(Motivo), io_lib:format(<<"{\"error\":\"HTTP 502\",\"message\":\"~p\"}"/utf8>>, [Motivo])).
-define(HTTP_ERROR_502, <<"{\"error\":\"HTTP 502\",\"message\":\"eservice_failed\"}"/utf8>>).
-define(HTTP_ERROR_503, <<"{\"error\":\"HTTP 503\",\"message\":\"eunavailable_service\"}"/utf8>>).


