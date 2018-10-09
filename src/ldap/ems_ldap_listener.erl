%%********************************************************************
%% @title Module ems_ldap_listener
%% @version 1.0.0
%% @doc Listener module for ldap server
%% @author Everton de Vargas Agilar <evertonagilar@gmail.com>
%% @copyright ErlangMS Team
%%********************************************************************

-module(ems_ldap_listener).

-behavior(gen_server). 

-include("../include/ems_config.hrl").
-include("../include/ems_schema.hrl").

%% Server API
-export([start/4, stop/0]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/1, handle_info/2, terminate/2, code_change/3]).


-record(state, {listener_name,
				server_name,
				ldap_admin,	 			 %% admin ldap. Ex.: cn=admin,dc=unb,dc=br
				ldap_admin_cn, 			 %% admin ldap. Ex.: admin
				ldap_admin_base_filter,	 %% admin base filter. Ex.: dc=unb,dc=br
				ldap_admin_password,     %% Password of admin ldap
				base_search,
				tcp_allowed_address_t,
				bind_cn_success_metric_name,
				bind_uid_success_metric_name,
				bind_success_metric_name,
				bind_cn_invalid_credential_metric_name,
				bind_uid_invalid_credential_metric_name,
				bind_invalid_credential_metric_name,
				search_invalid_credential_metric_name,
				search_unavailable_metric_name,
				search_success_metric_name,
				host_denied_metric_name,
				error_metric_name,
				request_capabilities_metric_name,
				auth_allow_user_inative_credentials
			}).   




-define(SERVER, ?MODULE).

%%====================================================================
%% Server API
%%====================================================================

start(IpAddress, Service, ListenerName, ServerName) -> 
    gen_server:start_link(?MODULE, {IpAddress, Service, ListenerName, ServerName}, []).
 
stop() ->
    gen_server:cast(?SERVER, shutdown).
 

 
%%====================================================================
%% gen_server callbacks
%%====================================================================
 
init({IpAddress, 
	  #service{protocol = Protocol,
			   tcp_port = Port, 
			   tcp_allowed_address_t = AllowedAddress,
			   auth_allow_user_inative_credentials = AuthAllowUserInativeCredentials,
			   properties = Props}, 
	  ListenerName,
	  ServerName}) ->
	ProtocolStr = binary_to_list(Protocol),
	IpAddressStr = inet_parse:ntoa(IpAddress),
	BindCnSuccessMetricName = erlang:binary_to_atom(iolist_to_binary([ServerName, <<"_bind_cn_success">>]), utf8),
	BindUidSuccessMetricName = erlang:binary_to_atom(iolist_to_binary([ServerName, <<"_bind_uid_success">>]), utf8),
	BindSuccessMetricName = erlang:binary_to_atom(iolist_to_binary([ServerName, <<"_bind_success">>]), utf8),
	BindCnInvalidCredentialMetricName = erlang:binary_to_atom(iolist_to_binary([ServerName, <<"_bind_cn_invalid_credential">>]), utf8),
	BindUidInvalidCredentialMetricName = erlang:binary_to_atom(iolist_to_binary([ServerName, <<"_bind_uid_invalid_credential">>]), utf8),
	BindInvalidCredentialMetricName = erlang:binary_to_atom(iolist_to_binary([ServerName, <<"_bind_invalid_credential">>]), utf8),
	SearchInvalidCredentialMetricName = erlang:binary_to_atom(iolist_to_binary([ServerName, <<"_search_invalid_credential">>]), utf8),
	SearchUnavailableMetricName = erlang:binary_to_atom(iolist_to_binary([ServerName, <<"_search_unavailable_credential">>]), utf8),
	SearchSuccessMetricName = erlang:binary_to_atom(iolist_to_binary([ServerName, <<"_search_success">>]), utf8),
	HostDeniedMetricName = erlang:binary_to_atom(iolist_to_binary([ServerName, <<"_host_denied">>]), utf8),
	ErrorMetricName = erlang:binary_to_atom(iolist_to_binary([ServerName, <<"_error_denied">>]), utf8),
	RequestCapabilitiesMetricName = erlang:binary_to_atom(iolist_to_binary([ServerName, <<"_request_capabilities">>]), utf8),
	LdapAdmin = ems_config:getConfig(<<"ldap_admin">>, ServerName, maps:get(<<"ldap_admin">>, Props)),
	case ems_util:parse_ldap_name(LdapAdmin) of
		{ok, _, LdapAdminCnValue, LdapAdminBaseFilterValue} -> 
			LdapAdminCn = LdapAdminCnValue,
			LdapAdminBaseFilter = LdapAdminBaseFilterValue;
		{error, Reason} -> 
			LdapAdminCn = LdapAdmin,
			LdapAdminBaseFilter = <<>>,
			ems_logger:error("ems_ldap_listener parse ldap_admin fail. Reason: ~p.", [Reason])
	end,
	LdapPasswdAdmin0 = ems_config:getConfig(<<"ldap_password_admin">>, ServerName, maps:get(<<"ldap_password_admin">>, Props)),
    LdapPasswdAdminCrypto = ems_config:getConfig(<<"ldap_password_admin_crypto">>, ServerName, maps:get(<<"ldap_password_admin_crypto">>, Props)),
    LdapPasswdAdmin = case LdapPasswdAdminCrypto of
							<<"SHA1">> -> LdapPasswdAdmin0;
							_ -> ems_util:criptografia_sha1(LdapPasswdAdmin0)
					  end,
    LdapBaseSearch = ems_config:getConfig(<<"ldap_base_search">>, ServerName, maps:get(<<"ldap_base_search">>, Props)),
    State = #state{ldap_admin = LdapAdmin,
				   ldap_admin_cn = LdapAdminCn,
				   ldap_admin_base_filter = LdapAdminBaseFilter,
				   ldap_admin_password = LdapPasswdAdmin,
				   base_search = LdapBaseSearch,
				   tcp_allowed_address_t = AllowedAddress,
				   listener_name = ListenerName,
				   server_name = ServerName,
				   bind_cn_success_metric_name = BindCnSuccessMetricName,
				   bind_uid_success_metric_name = BindUidSuccessMetricName,
				   bind_success_metric_name = BindSuccessMetricName,
				   bind_cn_invalid_credential_metric_name = BindCnInvalidCredentialMetricName,
				   bind_uid_invalid_credential_metric_name = BindUidInvalidCredentialMetricName,
				   bind_invalid_credential_metric_name = BindInvalidCredentialMetricName,
				   search_invalid_credential_metric_name = SearchInvalidCredentialMetricName,
				   search_unavailable_metric_name = SearchUnavailableMetricName,
				   search_success_metric_name = SearchSuccessMetricName,
				   host_denied_metric_name = HostDeniedMetricName,
				   error_metric_name = ErrorMetricName,
				   request_capabilities_metric_name = RequestCapabilitiesMetricName,
				   auth_allow_user_inative_credentials = AuthAllowUserInativeCredentials
			   },
	Ret = ranch:start_listener(ListenerName, ranch_tcp, #{socket_opts => [{ip, IpAddress}, 
																	      {port, Port}]}, 
	
							   ems_ldap_handler, [State]),
	case Ret of
		{ok, _PidCowboy} -> 
			ems_logger:info("ems_ldap_listener listener ~s in ~s:~p.", [ProtocolStr, IpAddressStr, Port]);
		{error,eaddrinuse} -> 
			ems_logger:error("ems_ldap_listener can not listen ~s on port ~p because it is already in use on IP ~s by other process.", [ProtocolStr, Port, IpAddressStr])
	end,
	{ok, State}.
		
handle_cast(shutdown, State) ->
    {stop, normal, State}.
    
handle_call(_Msg, _From, State) ->
    {reply, ok, State}.
    
handle_info(timeout, State) ->  {noreply, State}.

handle_info(State) -> {noreply, State}.

terminate(_Reason, _State) -> ok.
 
code_change(_OldVsn, State, _Extra) -> {ok, State}.


