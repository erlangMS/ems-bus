%%********************************************************************
%% @title Module ems_ldap_handler
%% @version 1.0.0
%% @doc Process ldap messages
%% @author Everton de Vargas Agilar <evertonagilar@gmail.com>
%% @copyright ErlangMS Team
%%********************************************************************

-module(ems_ldap_handler).

-behaviour(ranch_protocol).

-include("include/ems_config.hrl").
-include("include/ems_schema.hrl").
-include("include/LDAP.hrl").

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


-export([start_link/4]).
-export([init/4]).

start_link(Ref, Socket, Transport, Service) ->
	Pid = spawn_link(?MODULE, init, [Ref, Socket, Transport, Service]),
	{ok, Pid}.

init(Ref, Socket, Transport, [State]) ->
	ranch:accept_ack(Ref),
	loop(Socket, Transport, State).

loop(Socket, Transport, State = #state{tcp_allowed_address_t = AllowedAddress,
									   host_denied_metric_name = HostDeniedMetricName,
									   error_metric_name = ErrorMetricName}) ->
	case Transport:recv(Socket, 0, ?LDAP_MAX_SIZE_PACKET) of
		{ok, Data} ->
			case inet:peername(Socket) of
				{ok, {IpTuple, Port}} ->
					IpBin = list_to_binary(inet_parse:ntoa(IpTuple)),
					case ems_util:allow_ip_address(IpTuple, AllowedAddress) of				
						true ->
							case decode_ldap_message(Data) of
								{ok, LdapMessage} ->
									ems_logger:debug2("ems_ldap_handler request: ~p\n.", [LdapMessage]),
									MessageID = LdapMessage#'LDAPMessage'.messageID,
									TimestampBin = ems_util:timestamp_binary(),
									Result = handle_request(LdapMessage, State, IpBin, Port, TimestampBin),
									case Result of
										{ok, unbindRequest} ->
											%BindReqHash = erlang:phash2([IpBin, Port]),
											%erase(BindReqHash),
											%Transport:close(Socket),
											?DEBUG("ems_ldap_handler unbindRequest and close socket."),
											ok;
										{ok, Msg} -> 
											?DEBUG("ems_ldap_handler response: ~p.", [Msg]),
											Response = [ encode_response(MessageID, M) || M <- Msg ],
											Transport:send(Socket, Response)
									end;
								{error, Reason} ->
									ems_db:inc_counter(ErrorMetricName),
									ems_logger:error("ems_ldap_handler decode invalid message ~p from ~p. Reason: ~p.", [Data, IpBin, Reason]),
									ResultDone = make_result_done(inappropriateMatching),
									Response = [ encode_response(1, ResultDone) ],
									Transport:send(Socket, Response),
									Transport:close(Socket),
									ok
							end;
						false ->
							ems_db:inc_counter(HostDeniedMetricName),
							ems_logger:warn("ems_ldap_handler does not grant access to IP ~p. Reason: IP denied.", [IpBin]),
							ResultDone = make_result_done(insufficientAccessRights),
							Response = [ encode_response(1, ResultDone) ],
							Transport:send(Socket, Response),
							Transport:close(Socket),
							ok
					end;
				Error -> 
					ems_db:inc_counter(ErrorMetricName),
					ems_logger:error("ems_ldap_handler peername error. Reason: ~p.", [Error]),
					Transport:close(Socket),
					ok
			end,
			loop(Socket, Transport, State);		
		_ ->
			Transport:close(Socket),
			ok
	end.


encode_response(MessageID, Msg) ->
	Response = #'LDAPMessage'{messageID = MessageID,
							  protocolOp = Msg,
							  controls = asn1_NOVALUE},
    case 'LDAP':encode('LDAPMessage', Response) of
        {ok, Result} -> Result;
        {error, Reason} -> {error, Reason}
    end.


decode_ldap_message(RequestBin) ->
	case 'LDAP':decode('LDAPMessage', RequestBin) of
        {ok, {'LDAPMessage', _MessageID, _ProtocolOp, _} = LdapMsg} -> {ok, LdapMsg};
		Error -> Error
    end.

  
handle_request(LdapMessage = {'LDAPMessage', _,
								{bindRequest, #'BindRequest'{version = _Version, 
															 name = Name, 
															 authentication = {_, Password}}},
							 _}, 
			   State, Ip, Port, TimestampBin) ->
	handle_bind_request(Name, Password, State, Ip, Port, TimestampBin, LdapMessage#'LDAPMessage'.messageID);


handle_request({'LDAPMessage', _,
					{searchRequest, #'SearchRequest'{baseObject = _BaseObject, 
													 scope = singleLevel, % wholeSubtree or baseObject or singleLevel
													 derefAliases = _DerefAliases,  % derefAlways or neverDerefAliases
													 sizeLimit = _SizeLimit, 
													 timeLimit = _TimeLimit, 
													 typesOnly = _TypesOnly, 
													 filter =  {equalityMatch, {'AttributeValueAssertion', _Attribute = <<"roleOccupant">>, ObjectName}},
													 attributes = _Attributes}},
				 _}, #state{search_invalid_credential_metric_name = SearchInvalidCredentialMetricName,
							search_success_metric_name = SearchSuccessMetricName,
							auth_allow_user_inative_credentials = AuthAllowUserInativeCredentials}, 
					Ip, Port, TimestampBin) ->
	case ems_util:parse_ldap_name(ObjectName) of
		{ok, _, UserLogin, _BaseFilter} ->
			case ems_user:find_by_login(UserLogin) of
				{error, Reason, ReasonDetail} ->
					ems_db:inc_counter(SearchInvalidCredentialMetricName),
					ems_logger:error("ems_ldap_handler handle_request search ~p does not exist from ~p.", [UserLogin, Ip]),
					ems_user:add_history(#user{login = UserLogin}, 
										 #service{}, 
										 #request{timestamp = TimestampBin,
												  code = ?LDAP_INVALID_CREDENTIALS,
												  reason = Reason,
												  reason_detail = ReasonDetail,
												  operation = search_login,
												  host = Ip,
												  protocol = ldap,
												  port = Port}),
					ResultDone = make_result_done(invalidCredentials),
					{ok, [ResultDone]};
				{ok, User = #user{active = Active}} -> 
						case Active orelse AuthAllowUserInativeCredentials of
							true -> 
								ems_db:inc_counter(SearchSuccessMetricName),
								ems_logger:info("ems_ldap_handler handle_request search ~p ~p success from ~p.", [UserLogin, User#user.name, Ip]),
								{ok, ListaPerfil} = ems_user_perfil:find_by_user(User#user.id, [id, name]),
								ListaPerfil2 = [ maps:get(<<"name">>, R) || R <- ListaPerfil ],
								ResultEntry = {searchResEntry, #'SearchResultEntry'{objectName = ObjectName,
																	  attributes = [#'PartialAttribute'{type = <<"cn">>, vals = ListaPerfil2}]
																}
											  },
								ems_user:add_history(User, 
													 #service{}, 
													 #request{timestamp = TimestampBin,
															  code = ?LDAP_SUCCESS,
															  reason = success,
															  operation = role_occupant,
															  host = Ip,
															  protocol = ldap,
															  port = Port}),
								ResultDone = make_result_done(success),
								{ok, [ResultEntry, ResultDone]};
							false -> 
								ems_logger:error("ems_ldap_handler handle_request search ~p does not exist from ~p.", [UserLogin, Ip]),
								ems_user:add_history(User, 
													 #service{}, 
													 #request{timestamp = TimestampBin,
															  code = ?LDAP_INSUFFICIENT_ACCESS_RIGHTS,
															  reason = access_denied,
															  reason_detail = einative_user,
															  operation = search_login,
															  host = Ip,
															  protocol = ldap,
															  port = Port}),
								ResultDone = make_result_done(insufficientAccessRights),
								{ok, [ResultDone]}
						end
			end;
		{error, Reason} -> 
			ems_logger:error("ems_ldap_handler handle_request parse invalid name ~p from ~p.", [ObjectName, Ip]),
			ems_user:add_history(#user{login = ObjectName},  
								 #service{}, 
								 #request{timestamp = TimestampBin,
										  code = ?LDAP_INSUFFICIENT_ACCESS_RIGHTS,
										  reason = access_denied,
										  reason_detail = einvalid_search_name,
										  reason_exception = Reason,
										  operation = bind_request,
										  host = Ip,
										  protocol = ldap,
										  port = Port}),
			ResultDone = make_result_done(invalidCredentials),
			{ok, [ResultDone]}
	end;

% sei e redmine
handle_request({'LDAPMessage', _,
					{searchRequest, #'SearchRequest'{baseObject = _BaseObject, 
													 scope = _Scope, % wholeSubtree or baseObject or singleLevel
													 derefAliases = _DerefAliases,  % derefAlways or neverDerefAliases
													 sizeLimit = _SizeLimit, 
													 timeLimit = _TimeLimit, 
													 typesOnly = _TypesOnly, 
													 filter =  {equalityMatch, {'AttributeValueAssertion', Attribute, Value}},
													 attributes = Attributes}},
				 _}, State, Ip, Port, TimestampBin) ->
	handle_request_search_login(Value, Attribute, State, Ip, Port, TimestampBin, Attributes);


% isGlobalCatalogReady
handle_request({'LDAPMessage', _,
					{searchRequest, #'SearchRequest'{baseObject = <<>>, 
													 scope = _Scope, 
													 derefAliases = _DerefAliases, 
													 sizeLimit = _SizeLimit, 
													 timeLimit = _TimeLimit, 
													 typesOnly = _TypesOnly, 
													 filter = {present, <<"objectClass">>}, attributes = [<<"isGlobalCatalogReady">>]}},
				 _}, _State, Ip, Port, TimestampBin) ->
	ResultEntry = {searchResEntry, #'SearchResultEntry'{objectName = <<>>,
										  attributes = [#'PartialAttribute'{type = <<"isGlobalCatalogReady">>, vals = [<<"ErlangMS">>]}]
										}
	},
	ems_user:add_history(#user{},  
						 #service{}, 
						 #request{timestamp = TimestampBin,
								  code = ?LDAP_SUCCESS,
								  reason = ok,
								  operation = is_global_catalog_ready,
								  host = Ip,
								  protocol = ldap,
								  port = Port}),
	ResultDone = make_result_done(success),
	{ok, [ResultEntry, ResultDone]};


% Search ObjectClass
handle_request({'LDAPMessage', _,
					{searchRequest, #'SearchRequest'{baseObject = _BaseObject, 
													 scope = _Scope, 
													 derefAliases = _DerefAliases, 
													 sizeLimit = _SizeLimit, 
													 timeLimit = _TimeLimit, 
													 typesOnly = _TypesOnly, 
													 filter = {present, ObjectClass}, 
													 attributes = Attributes}},
				 _}, State, Ip, Port, TimestampBin) ->
	handle_request_search_login(ObjectClass, <<>>, State, Ip, Port, TimestampBin, Attributes);


% Filter or
handle_request({'LDAPMessage', _,
					{searchRequest, #'SearchRequest'{baseObject = _BaseObject, 
													 scope = _Scope, 
													 derefAliases = _DerefAliases, 
													 sizeLimit = _SizeLimit, 
													 timeLimit = _TimeLimit, 
													 typesOnly = _TypesOnly, 
													 filter = FilterOr = {'or', _}, 
													 attributes = Attributes}},
				 _}, State, Ip, Port, TimestampBin) ->
	handle_request_search_filter(FilterOr, State, Ip, Port, TimestampBin, Attributes);

% Filter and
handle_request({'LDAPMessage', _,
					{searchRequest, #'SearchRequest'{baseObject = _BaseObject, 
													 scope = _Scope, 
													 derefAliases = _DerefAliases, 
													 sizeLimit = _SizeLimit, 
													 timeLimit = _TimeLimit, 
													 typesOnly = _TypesOnly, 
													 filter = FilterAnd = {'and', _}, 
													 attributes = Attributes}},
				 _}, State, Ip, Port, TimestampBin) ->
	handle_request_search_filter(FilterAnd, State, Ip, Port, TimestampBin, Attributes);


handle_request({'LDAPMessage', _, 
					{unbindRequest, _},
				 _}, _State, _Ip, _Port, _TimestampBin) ->
	{ok, unbindRequest};
	
handle_request({'LDAPMessage', _, 
					_UnknowMsg,
				 _} = LdapMsg, _State, Ip, _Port, _TimestampBin) ->
	ems_logger:warn("ems_ldap_handler handle_request received unknow msg ~p from ~p.", [LdapMsg, Ip]),
	{ok, unbindRequest}.
	

make_object_name(UsuId) ->
	R1 = [<<"uid="/utf8>>, UsuId, <<",dc=unb,dc=br"/utf8>>],
	R2 = iolist_to_binary(R1),
	R2.

make_bind_response(unavailable, _) ->
	make_bind_response(unavailable, <<"">>, <<"LDAP unavailable!!!">>);

make_bind_response(ResultCode, MatchedDN) ->
	make_bind_response(ResultCode, MatchedDN, <<"">>).

make_bind_response(ResultCode, MatchedDN, DiagnosticMessage) ->
	{bindResponse, #'BindResponse'{resultCode = ResultCode,
												  matchedDN = MatchedDN,
												  diagnosticMessage = DiagnosticMessage,
												  referral = asn1_NOVALUE,
												  serverSaslCreds = asn1_NOVALUE}
	}.



make_result_entry_item(#user{id = UsuId, 
							 codigo = CodigoPessoa,
							 login = UsuLogin,	
							 password = UsuPassword,
							 name = UsuName, 
							 cpf = UsuCpf, 
							 email = UsuEmail, 
							 type = UsuType, 
							 subtype = UsuSubType,
							 type_email = UsuTypeEmail, 
							 ctrl_insert = UsuCtrlInsert, 
							 ctrl_update = UsuCtrlUpdate,
							 ctrl_last_login = UsuCtrlLastLogin,
							 ctrl_login_count = UsuCtrlLoginCount,
							 active = Active,
							 endereco = Endereco,
							 complemento_endereco = ComplementoEndereco,
							 bairro = Bairro,
							 cidade = Cidade,
							 uf = UF,
							 cep = Cep,
							 rg = RG,
							 data_nascimento = DataNascimento,
							 sexo = Sexo,
							 telefone = Telefone,
							 celular = Celular,
							 ddd = DDD,
							 nome_pai = NomePai,
							 nome_mae = NomeMae,
							 nacionalidade = Nacionalidade
				}, 
				  AdminLdap, AtrributesToReturn) ->
	UsuId2 = format_user_field(UsuId),
	ObjectName = make_object_name(UsuLogin),
	CodigoPessoa2 = format_user_field(CodigoPessoa),
	UsuName2 = format_user_field(UsuName),
	UsuLogin2 = format_user_field(UsuLogin),
	UsuCpf2 = format_user_field(UsuCpf),
	UsuEmail2 = format_user_field(UsuEmail),
	UsuType2 = format_user_field(UsuType),
	UsuSubType2 = format_user_field(UsuSubType),
	UsuTypeEmail2 = format_user_field(UsuTypeEmail),
	UsuCtrlInsert2 = format_user_field(UsuCtrlInsert),
	UsuCtrlUpdate2 = format_user_field(UsuCtrlUpdate),
	UsuCtrlLastLogin2 = format_user_field(UsuCtrlLastLogin),
	UsuCtrlLoginCount2 = format_user_field(UsuCtrlLoginCount),
	Active2 = format_user_field(Active),
	Endereco2 = format_user_field(Endereco),
	ComplementoEndereco2 = format_user_field(ComplementoEndereco),
	Bairro2 = format_user_field(Bairro),
	Cidade2 = format_user_field(Cidade),
	UF2 = format_user_field(UF),
	Cep2 = format_user_field(Cep),
	RG2 = format_user_field(RG),
	DataNascimento2 = format_user_field(DataNascimento),
	Sexo2 = format_user_field(Sexo),
	Telefone2 = format_user_field(Telefone),
	Celular2 = format_user_field(Celular),
	DDD2 = format_user_field(DDD),
	NomePai2 = format_user_field(NomePai),
	NomeMae2 = format_user_field(NomeMae),
	Nacionalidade2 = format_user_field(Nacionalidade),
	case binary:split(UsuName2, <<" ">>) of
		[FirstNameValue, LastNameValue] -> 
			SN = LastNameValue,
			GivenName = FirstNameValue;
		[FirstNameValue] -> 
			SN = <<>>,
			GivenName = FirstNameValue;
		_ ->	
			SN = <<>>,
			GivenName = <<>>
	end,

	% Valida os atributos de retorno
	AtrributesToReturn2 = ems_util:parse_ldap_attributes(AtrributesToReturn),

	% Perfils são roles no LDAP
	{ok, ListaPerfil} = ems_user_perfil:find_by_user(UsuId, [id, name]),
	ListaPerfil2 = lists:usort([ maps:get(<<"name">>, R) || R <- ListaPerfil ]),

	Attributes = [  #'PartialAttribute'{type = <<"uid">>, vals = [UsuId2]},
					#'PartialAttribute'{type = <<"employeeNumber">>, vals = [UsuId2]},
					#'PartialAttribute'{type = <<"uidNumber">>, vals = [UsuId2]},
					#'PartialAttribute'{type = <<"objectClass">>, vals = [<<"person">>]},
					#'PartialAttribute'{type = <<"objectClass">>, vals = [<<"organizationalPerson">>]},
					#'PartialAttribute'{type = <<"objectClass">>, vals = [<<"inetOrgPerson">>]},
					#'PartialAttribute'{type = <<"objectClass">>, vals = [<<"posixAccount">>]},
					#'PartialAttribute'{type = <<"gecos">>, vals = [UsuName2]},
					#'PartialAttribute'{type = <<"cn">>, vals = [UsuLogin2]},						 % full use name
					#'PartialAttribute'{type = <<"givenName">>, vals = [GivenName]},	 			 % primeiro nome
					#'PartialAttribute'{type = <<"sn">>, vals = [SN]},					  		     % último nome
					#'PartialAttribute'{type = <<"memberUid">>, vals = [UsuId2]},
					#'PartialAttribute'{type = <<"member">>, vals = [UsuName2]},     	  			 % full user name in Active Directory
					#'PartialAttribute'{type = <<"sAMAccountName">>, vals = [GivenName]}, 			 % shortened user name in Active Directory
					#'PartialAttribute'{type = <<"displayName">>, vals = [UsuName2]},    		 	 % full user name in Active Directory
					#'PartialAttribute'{type = <<"distinguishedName">>, vals = [UsuLogin2]},  		 % SEI usa no campo atributo de retorno
					#'PartialAttribute'{type = <<"creatorsName">>, vals = [AdminLdap]},
					#'PartialAttribute'{type = <<"namingContexts">>, vals = [<<"dc=unb,dc=br">>]},
					#'PartialAttribute'{type = <<"o">>, vals = [<<"UnB">>]},
					#'PartialAttribute'{type = <<"mail">>, vals = [UsuEmail2]},
					#'PartialAttribute'{type = <<"email">>, vals = [UsuEmail2]},
					#'PartialAttribute'{type = <<"codigo">>, vals = [CodigoPessoa2]},
					#'PartialAttribute'{type = <<"login">>, vals = [UsuLogin2]},
					#'PartialAttribute'{type = <<"name">>, vals = [UsuName2]},
					#'PartialAttribute'{type = <<"cpf">>, vals = [UsuCpf2]},
					#'PartialAttribute'{type = <<"passwd">>, vals = [UsuPassword]},
					#'PartialAttribute'{type = <<"roles">>, vals = ListaPerfil2},
					%#'PartialAttribute'{type = <<"roleOccupant">>, vals = ListaPerfil2},
					#'PartialAttribute'{type = <<"active">>, vals = [Active2]},
					#'PartialAttribute'{type = <<"endereco">>, vals = [Endereco2]},
					#'PartialAttribute'{type = <<"complemento_endereco">>, vals = [ComplementoEndereco2]},
					#'PartialAttribute'{type = <<"bairro">>, vals = [Bairro2]},
					#'PartialAttribute'{type = <<"cidade">>, vals = [Cidade2]},
					#'PartialAttribute'{type = <<"uf">>, vals = [UF2]},
					#'PartialAttribute'{type = <<"cep">>, vals = [Cep2]},
					#'PartialAttribute'{type = <<"rg">>, vals = [RG2]},
					#'PartialAttribute'{type = <<"dataNascimento">>, vals = [DataNascimento2]},
					#'PartialAttribute'{type = <<"sexo">>, vals = [Sexo2]},
					#'PartialAttribute'{type = <<"telefone">>, vals = [Telefone2]},
					#'PartialAttribute'{type = <<"celular">>, vals = [Celular2]},
					#'PartialAttribute'{type = <<"ddd">>, vals = [DDD2]},
					#'PartialAttribute'{type = <<"nome_pai">>, vals = [NomePai2]},
					#'PartialAttribute'{type = <<"nome_mae">>, vals = [NomeMae2]},
					#'PartialAttribute'{type = <<"nacionalidade">>, vals = [Nacionalidade2]},
					#'PartialAttribute'{type = <<"type">>, vals = [UsuType2]},
					#'PartialAttribute'{type = <<"subtype">>, vals = [UsuSubType2]},
					#'PartialAttribute'{type = <<"type_email">>, vals = [UsuTypeEmail2]},
					#'PartialAttribute'{type = <<"ctrl_insert">>, vals = [UsuCtrlInsert2]},
					#'PartialAttribute'{type = <<"ctrl_update">>, vals = [UsuCtrlUpdate2]},
					#'PartialAttribute'{type = <<"ctrl_last_login">>, vals = [UsuCtrlLastLogin2]},
					#'PartialAttribute'{type = <<"ctrl_login_count">>, vals = [UsuCtrlLoginCount2]},
					#'PartialAttribute'{type = <<"supportedCapabilities">>, vals = [<<"yes">>]},
					#'PartialAttribute'{type = <<"supportedControl">>, vals = [<<"no">>]},
					#'PartialAttribute'{type = <<"supportedExtension">>, vals = [<<"no">>]},
					#'PartialAttribute'{type = <<"supportedFeatures">>, vals = [<<"no">>]},
					#'PartialAttribute'{type = <<"supportedLdapVersion">>, vals = [<<"3">>]},
					#'PartialAttribute'{type = <<"supportedSASLMechanisms">>, vals = [<<"no">>]}
				],

	% Filtra os atributos de retorno. Retornar somente os que o cliente pediu
	case AtrributesToReturn2 of
		[] -> Attributes2 = Attributes;
		_ -> Attributes2 = [ R || R <- Attributes, lists:member(R#'PartialAttribute'.type, AtrributesToReturn2) ]
	end,

	#'SearchResultEntry'{objectName = ObjectName,
										  attributes = Attributes2
										}.


%make_result_entry_list_([], _, _, ItemList) -> 
%	{searchResEntry, ItemList};
%make_result_entry_list_([H|T], AdminLdap, AtrributesToReturn, ItemList) ->
%	Item = make_result_entry_item(H, AdminLdap, AtrributesToReturn),
%	make_result_entry_list_(T, AdminLdap, AtrributesToReturn, [Item | ItemList]).

%make_result_entry_list(L, AdminLdap, AtrributesToReturn) -> make_result_entry_list_(L, AdminLdap, AtrributesToReturn, []).

make_result_entry(User, AdminLdap, AtrributesToReturn) -> 
	Item = make_result_entry_item(User, AdminLdap, AtrributesToReturn),
	{searchResEntry, Item}.

											


make_result_done(ResultCode) ->
	{searchResDone, #'LDAPResult'{resultCode = ResultCode, 
								  matchedDN = <<"">>, 
								  diagnosticMessage = <<"">>,
								  referral = asn1_NOVALUE}
	
	}.


handle_bind_request(Name, 
						  Password, 
						  State = #state{base_search = _BaseSearchConfig},
						  Ip, Port, TimestampBin, _MessageID) ->
	NameSize = byte_size(Name),
	PasswordSize = byte_size(Password),
	case (Name =:= <<>>) orelse (NameSize < 2) orelse (NameSize > 100) orelse 
		 (Password =:= <<>>) orelse (PasswordSize < 1) orelse (PasswordSize > 256) of
		true ->
			ems_logger:error("ems_ldap_handler handle_bind_request parse invalid bind request name ~p from ~p.", [Name, Ip]),
			ems_user:add_history(#user{login = Name},  
								 #service{}, 
								 #request{timestamp = TimestampBin,
										  code = ?LDAP_INSUFFICIENT_ACCESS_RIGHTS,
										  reason = access_denied,
										  reason_detail = einvalid_bind_request_name,
										  reason_exception = einvalid_name,
										  operation = bind_request,
										  host = Ip,
										  protocol = ldap,
										  port = Port}),
			BindResponse = make_bind_response(invalidCredentials, Name);
		false ->
			case ems_util:parse_ldap_name(Name) of
				{ok, UidOrCn, AdminLogin, _LdapAdminBaseFilter} ->
					case do_authenticate_admin_with_admin_user(Name, AdminLogin, Password, State, Ip, Port, TimestampBin) of
						{ok, IsAdmin} -> 
							BindReqHash = erlang:phash2([Ip, Port]),
							put(BindReqHash, {IsAdmin, AdminLogin}),
							ems_logger:info("ems_ldap_handler handle_bind_request bind_~s ~p success from ~p.", [atom_to_list(UidOrCn), Name, Ip]),
							BindResponse = make_bind_response(success, Name);
						_ ->
						  case do_authenticate_admin_with_list_users(AdminLogin, Password, State, Ip, Port, TimestampBin) of
							  {ok, #user{admin = IsAdmin, ctrl_source_type = Table}} -> 
								 BindReqHash = erlang:phash2([Ip, Port]),
								 put(BindReqHash, {IsAdmin, AdminLogin}),
								 ems_logger:info("ems_ldap_handler handle_bind_request bind_~s ~p on table ~p success from ~p.", [atom_to_list(UidOrCn), Name, Table, Ip]),
								 BindResponse = make_bind_response(success, Name);
							  _-> 
								 ems_logger:error("ems_ldap_handler handle_bind_request bind_~s ~p invalid credential from ~p.", [atom_to_list(UidOrCn), Name, Ip]),
								 BindResponse = make_bind_response(insufficientAccessRights, Name)
						   end
					end,
					BindResponse;
				{error, Reason} -> 
					ems_logger:error("ems_ldap_handler handle_bind_request parse invalid bind request name ~p from ~p.", [Name, Ip]),
					ems_user:add_history(#user{login = Name},  
										 #service{}, 
										 #request{timestamp = TimestampBin,
												  code = ?LDAP_INSUFFICIENT_ACCESS_RIGHTS,
												  reason = access_denied,
												  reason_detail = einvalid_bind_request_name,
												  reason_exception = Reason,
												  operation = bind_request,
												  host = Ip,
												  protocol = ldap,
												  port = Port}),
					BindResponse = make_bind_response(invalidCredentials, Name)
			end
	end,
	{ok, [BindResponse]}.
	

-spec handle_request_search_login(binary(), binary(), #state{}, binary(), non_neg_integer(), binary(), list(binary())) -> {ok, tuple()}.
handle_request_search_login(Name, 
						    Attribute,
							State = #state{search_invalid_credential_metric_name = SearchInvalidCredentialMetricName,
										   search_success_metric_name = SearchSuccessMetricName}, 
										   Ip, Port, TimestampBin, AttributesToReturn) ->	
	case ems_util:parse_ldap_name(Name) of
		{ok, _, UserLogin, _BaseFilter} ->
			{IsAdmin, BindRequestName} = get_bind_user(Ip, Port, UserLogin),
			case ems_user:find_by_login(UserLogin) of
				{error, Reason, ReasonDetail} ->
					ems_db:inc_counter(SearchInvalidCredentialMetricName),
					case Attribute of
						<<>> ->
							case BindRequestName of
								<<>> -> ems_logger:error("ems_ldap_handler handle_request_search_login unbind search ~p does not exist from ~p.", [UserLogin, Ip]);
								_ -> ems_logger:error("ems_ldap_handler handle_request_search_login search ~p does not exist by ~p from ~p.", [UserLogin, BindRequestName, Ip])
							end,
							ems_user:add_history(#user{login = UserLogin}, 
												 #service{}, 
												 #request{timestamp = TimestampBin,
														  code = ?LDAP_NO_SUCH_OBJECT,
														  reason = Reason,
														  reason_detail = ReasonDetail,
														  operation = search_login,
														  host = Ip,
														  protocol = ldap,
														  port = Port}),
							ResultDone = make_result_done(noSuchObject),
							{ok, [ResultDone]};
						_ -> 
							case ems_util:ldap_attribute_map_to_user_field(Attribute) of
								{ok, Field} -> 
									do_find_by_filter([{Field, <<"==">>, Name}], State, Ip, Port, TimestampBin, AttributesToReturn, UserLogin);
								{error, einvalid_field} ->
									case BindRequestName of
										<<>> -> ems_logger:error("ems_ldap_handler handle_request_search_login unbind search ~p does not exist from ~p.", [UserLogin, Ip]);
										_ -> ems_logger:error("ems_ldap_handler handle_request_search_login search ~p does not exist by ~p from ~p.", [UserLogin, BindRequestName, Ip])
									end,
									ems_user:add_history(#user{login = UserLogin}, 
														 #service{}, 
														 #request{timestamp = TimestampBin,
																  code = ?LDAP_NO_SUCH_ATTRIBUTE,
																  reason = einvalid_field,
																  reason_detail = noSuchAttribute,
																  operation = search_login,
																  host = Ip,
																  protocol = ldap,
																  port = Port}),
									ResultDone = make_result_done(noSuchAttribute),
									{ok, [ResultDone]}
							end
					end;
				{ok, User} -> 
					ems_db:inc_counter(SearchSuccessMetricName),
					case BindRequestName of
						<<>> -> 
							ems_logger:info("ems_ldap_handler handle_request_search_login unbind search ~p ~p success from ~p.", [UserLogin, User#user.name, Ip]),
							ResultEntry = make_result_entry(User, BindRequestName, [<<"uid">>]);
						_ -> 
							case IsAdmin of
								true -> 
									ems_logger:info("ems_ldap_handler handle_request_search_login admin search ~p ~p success by ~p from ~p.", [UserLogin, User#user.name, BindRequestName, Ip]),
									ResultEntry = make_result_entry(User, BindRequestName, AttributesToReturn);
								false -> 
									case (BindRequestName =:= UserLogin) of
										true -> 
											ems_logger:info("ems_ldap_handler handle_request_search_login user search ~p ~p success by ~p from ~p.", [UserLogin, User#user.name, BindRequestName, Ip]),
											ResultEntry = make_result_entry(User, BindRequestName, AttributesToReturn);
										false ->
											ems_logger:info("ems_ldap_handler handle_request_search_login restricted search ~p ~p success by ~p from ~p.", [UserLogin, User#user.name, BindRequestName, Ip]),
											ResultEntry = make_result_entry(User, BindRequestName, [<<"uid">>])
									end
							end
					end,
					ResultDone = make_result_done(success),
					ems_user:add_history(User, 
										 #service{}, 
										 #request{timestamp = TimestampBin,
												  code = ?LDAP_SUCCESS,
												  reason = success,
												  operation = search_login,
												  host = Ip,
												  protocol = ldap,
												  port = Port}),
					{ok, [ResultEntry, ResultDone]}
			end;
		{error, Reason} -> 
			ems_logger:error("ems_ldap_handler handle_request_search_login inappropriate matching name ~p from ~p.", [Name, Ip]),
			ems_user:add_history(#user{login = Name},  
								 #service{}, 
								 #request{timestamp = TimestampBin,
										  code = ?LDAP_INAPPROPRIATE_MATCHING,
										  reason = inappropriateMatching,
										  reason_detail = einvalid_search_name,
										  reason_exception = Reason,
										  operation = search_login,
										  host = Ip,
										  protocol = ldap,
										  port = Port}),
			ResultDone = make_result_done(inappropriateMatching),
			{ok, [ResultDone]}
	end.
	
-spec handle_request_search_filter(list(tuple()), #state{}, binary(), non_neg_integer(), binary(), list(binary())) -> {ok, tuple()}.
handle_request_search_filter(FilterLdap, State, Ip, Port, TimestampBin, AttributesToReturn) ->	
	case ems_util:parse_ldap_filter(FilterLdap) of
		{ok, Filter} -> 
			do_find_by_filter(Filter, State, Ip, Port, TimestampBin, AttributesToReturn, undefined);
		{error, Reason} -> 
			ems_logger:error("ems_ldap_handler handle_request_search_filter parse invalid filter or ~p from ~p.", [FilterLdap, Ip]),
			ems_user:add_history(#user{},  
								 #service{}, 
								 #request{timestamp = TimestampBin,
										  code = ?LDAP_INAPPROPRIATE_MATCHING,
										  reason = inappropriateMatching,
										  reason_detail = einvalid_search_request_filter_or,
										  reason_exception = Reason,
										  operation = search_filter_or,
										  host = Ip,
										  protocol = ldap,
										  port = Port}),
			BindResponse = make_bind_response(inappropriateMatching, <<>>),
			{ok, [BindResponse]}
	end.


do_find_by_filter(Filter, 
				  _State, 
				  Ip, Port, TimestampBin, AttributesToReturn, UserLogin) ->
	{IsAdmin, BindRequestName} = get_bind_user(Ip, Port, undefined),
	case ems_user:find_by_filter([], Filter) of
		{error, Reason, ReasonDetail} ->
			case BindRequestName of
				<<>> ->	ems_logger:error("ems_ldap_handler do_find_by_filter unbind search ~p does not exist from ~p.", [Filter, Ip]);
				_ -> ems_logger:error("ems_ldap_handler do_find_by_filter search ~p does not exist by ~p from ~p.", [Filter, BindRequestName, Ip])
			end,
			ems_user:add_history(#user{}, 
								 #service{}, 
								 #request{timestamp = TimestampBin,
										  code = ?LDAP_NO_SUCH_OBJECT,
										  reason = Reason,
										  reason_detail = ReasonDetail,
										  operation = search_filter_or,
										  host = Ip,
										  protocol = ldap,
										  port = Port}),
			ResultDone = make_result_done(noSuchObject),
			{ok, [ResultDone]};
		{ok, [User|_]} -> 
			case BindRequestName of
				<<>> -> 
					ems_logger:info("ems_ldap_handler do_find_by_filter unbind search ~p ~p success from ~p.", [Filter, User#user.name, Ip]),
					ResultEntry = make_result_entry(User, BindRequestName, [<<"uid">>]);
				_ -> 
					case IsAdmin of
						true -> 
							ems_logger:info("ems_ldap_handler do_find_by_filter admin search ~p ~p success by ~p from ~p.", [Filter, User#user.name, BindRequestName, Ip]),
							ResultEntry = make_result_entry(User, BindRequestName, AttributesToReturn);
						false -> 
							case (BindRequestName =:= UserLogin) of
								true -> 
									ems_logger:info("ems_ldap_handler do_find_by_filter user search ~p ~p success by ~p from ~p.", [Filter, User#user.name, BindRequestName, Ip]),
									ResultEntry = make_result_entry(User, BindRequestName, AttributesToReturn);
								false ->
									ems_logger:info("ems_ldap_handler do_find_by_filter restricted search ~p ~p success by ~p from ~p.", [Filter, User#user.name, BindRequestName, Ip]),
									ResultEntry = make_result_entry(User, BindRequestName, [<<"uid">>])
							end
					end
			end,
			ResultDone = make_result_done(success),
			ems_user:add_history(User, 
								 #service{}, 
								 #request{timestamp = TimestampBin,
										  code = ?LDAP_SUCCESS,
										  reason = success,
										  operation = search_filter_or,
										  host = Ip,
										  protocol = ldap,
										  port = Port}),
			{ok, [ResultEntry, ResultDone]};
		{ok, []} -> 
			case BindRequestName of
				<<>> ->	ems_logger:error("ems_ldap_handler do_find_by_filter unbind search ~p does not exist from ~p.", [Filter, Ip]);
				_ -> ems_logger:error("ems_ldap_handler do_find_by_filter search ~p does not exist by ~p from ~p.", [Filter, BindRequestName, Ip])
			end,
			ems_user:add_history(#user{}, 
								 #service{}, 
								 #request{timestamp = TimestampBin,
										  code = ?LDAP_NO_SUCH_OBJECT,
										  reason = enoent,
										  reason_detail = empty_list,
										  operation = find_by_filter,
										  host = Ip,
										  protocol = ldap,
										  port = Port}),
			ResultDone = make_result_done(noSuchObject),
			{ok, [ResultDone]}
	end.


% Autentica o admin a partir da base de usuários de users com flag admin = true	
do_authenticate_admin_with_list_users(UserLogin, UserPassword, #state{auth_allow_user_inative_credentials = AuthAllowUserInativeCredentials}, Ip, Port, TimestampBin) ->
	case ems_user:find_by_login_and_password(UserLogin, UserPassword, #client{name = <<"ldap">>, scope = ?CLIENT_DEFAULT_SCOPE}) of
		{ok, User = #user{active = Active}} -> 
			case Active orelse AuthAllowUserInativeCredentials of
				true -> 
					ems_user:add_history(User, 
										 #service{}, 
										 #request{timestamp = TimestampBin,
												  code = ?LDAP_SUCCESS,
												  reason = success,
												  operation = authenticate_admin,
												  host = Ip,
												  protocol = ldap,
												  port = Port}),
					{ok, User};
				false -> 
					ems_user:add_history(User, 
										 #service{}, 
										 #request{timestamp = TimestampBin,
												   code = ?LDAP_INSUFFICIENT_ACCESS_RIGHTS,
												   reason = access_denied,
												   reason_detail = einative_user,
												   operation = authenticate_admin,
												   host = Ip,
												   protocol = ldap,
												   port = Port}),
					{error, access_denied}
			end;
		{error, Reason, ReasonDetail} -> 
			% Para finalidades de debug, tenta buscar o user pelo login para armazenar no log
			case ems_user:find_by_login(UserLogin) of
				{ok, UserFound} -> User = UserFound;
				_ -> User = #user{login = UserLogin}
			end,
			ems_user:add_history(User,  
								 #service{}, 
								 #request{timestamp = TimestampBin,
										  code = ?LDAP_INSUFFICIENT_ACCESS_RIGHTS,
										  reason = Reason,
										  reason_detail = ReasonDetail,
										  operation = authenticate_admin,
										  host = Ip,
										  protocol = ldap,
										  port = Port}),
			{error, access_denied}
	end.

% Autentica o admin com o admin fornecido na configuração do processo ldap
do_authenticate_admin_with_admin_user(Name, LdapUser, PasswordUser, #state{ldap_admin = AdminLdapConfig, 
																		   ldap_admin_cn = AdminLdapCnConfig, 
																		   ldap_admin_password = PasswordAdminLdapConfig}, Ip, Port, TimestampBin) ->
	LdapUserLower = list_to_binary(string:to_lower(binary_to_list(LdapUser))),
	PasswordUserLower = list_to_binary(string:to_lower(binary_to_list(PasswordUser))),
	case (Name =:= AdminLdapConfig orelse 
		  LdapUser =:= AdminLdapConfig orelse
		  LdapUserLower =:= AdminLdapConfig orelse
		  LdapUser =:= AdminLdapCnConfig orelse
		  LdapUserLower =:= AdminLdapCnConfig) 
		  andalso 
		 (PasswordUser =:= PasswordAdminLdapConfig orelse 
		  ems_util:criptografia_sha1(PasswordUser) =:= PasswordAdminLdapConfig orelse
		  ems_util:criptografia_sha1(PasswordUserLower) =:= PasswordAdminLdapConfig) of
		true -> 
			ems_user:add_history(#user{login = LdapUser},  
								 #service{}, 
								 #request{timestamp = TimestampBin,
										  code = ?LDAP_SUCCESS,
										  reason = success,
										  operation = authenticate_admin,
										  host = Ip,
										  protocol = ldap,
										  port = Port}),
			{ok, true};
		false -> 
			ems_user:add_history(#user{login = LdapUser},  
								 #service{}, 
								 #request{timestamp = TimestampBin,
										  code = ?LDAP_INSUFFICIENT_ACCESS_RIGHTS,
										  reason = access_denied,
										  reason_detail = enoent,
										  operation = authenticate_admin,
										  host = Ip,
										  protocol = ldap,
										  port = Port}),
			{error, access_denied}
	end.
						 

format_user_field(undefined) -> <<"">>;
format_user_field(null) -> <<"">>;
format_user_field([]) -> <<"">>;
format_user_field(Value) when is_integer(Value) -> integer_to_binary(Value);
format_user_field(Value) when is_boolean(Value) -> ems_util:boolean_to_binary(Value);
format_user_field(Value) when is_list(Value) -> list_to_binary(Value);
format_user_field(Value) when is_binary(Value) -> Value.
	

-spec get_bind_user(binary(), non_neg_integer(), binary()) -> boolean().
get_bind_user(Ip, Port, _Name) -> 
	BindReqHash = erlang:phash2([Ip, Port]),
	case get(BindReqHash) of
		undefined -> {false, <<>>};
		{true, BindRequestName} -> {true, BindRequestName};
		{false, BindRequestName} -> {false, BindRequestName}
	end.

