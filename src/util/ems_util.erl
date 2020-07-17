%%********************************************************************
%% @title Module ems_util
%% @version 1.0.0
%% @doc Contains general purpose functions
%% @author Everton de Vargas Agilar <evertonagilar@gmail.com>
%% @copyright ErlangMS Team
%%********************************************************************

-module(ems_util).

-include("include/ems_config.hrl").
-include("include/ems_schema.hrl").


-export([version/0,
		 server_name/0,
		 sleep/1,
		 flush_messages/0,
		 json_encode/1,
		 json_decode/1,
		 hd_or_empty/1,
		 json_decode_as_map/1,
		 json_encode_table/2,
		 json_decode_as_map_file/1,
		 json_field_strip_and_escape/1,
		 tuple_to_binlist/1, 
		 list_to_integer_def/2,
		 binary_to_list_def/2,
		 binary_to_integer_def/2,
		 binlist_to_atomlist/1,
		 binlist_to_atomlist_with_trim/1,
		 list_to_atomlist_with_trim/1,
		 list_to_binlist/1,
		 atomlist_to_binlist/1,
		 atomlist_to_list/1,
		 mes_extenso/1,
		 binlist_to_list/1,
		 join_binlist/2,
		 list_to_ets/3,
		 profile/0,
		 make_rowid_from_url/2,
		 string_is_integer/1,
		 read_file_as_map/1,
		 read_file_as_list/1,
 		 read_file_as_string/1,
		 tail_file/2,
		 load_from_file_req/1,
		 save_from_file_req/1,
		 node_is_live/1,
 		 node_binary/0,
 		 get_environment_variable/1,
 		 get_environment_variable/2,
		 get_pid_from_port/1,
 		 get_free_tcp_port/0,
 		 get_host_list/0,
		 get_node_name/0,
		 get_params_from_url/1,
		 get_rowid_and_params_from_url/2,
		 get_priv_dir/0,
		 get_priv_dir_default/0,
		 get_working_dir/0,
		 get_home_dir/0,
 		 get_milliseconds/0,
		 get_param_url/3,
		 get_querystring/3,
		 get_querystring/4,
         get_querystring/2,
         get_client_request_by_id_and_secret/1,
         get_client_request_by_id/1,
         get_user_request_by_login_and_password/1,
         get_user_request_by_login_and_password/2,
         get_user_request_by_login/1,
         get_param_or_variable/3,
         get_java_home/0,
         get_www_path/0,
 		 get_log_file_path/0,
 		 get_log_file_archive_path/0,
         get_auth_default_scope/0,
         get_auth_password_check_between_scope/0,
         date_add_minute/2,
         date_dec_minute/2,
         date_add_second/2,
         date_dec_second/2,
		 date_add_day/2,
		 date_to_string/1,
		 date_to_binary/1,
		 date_diff_seconds/2,
		 time_to_binary/1,
 		 no_periodo/2,
 		 seconds_since_epoch/1,
 		 timestamp_str/0,
		 timestamp_str/1,
		 timestamp_binary/0,
		 timestamp_binary/1,
		 uptime_str/0,
		 boolean_to_binary/1,
		 value_to_boolean/1,
 		 replacenth/3,
		 replace/3,
		 replace_all/2,
		 replace_vars_with/2,
		 encrypt_public_key/2,
		 decrypt_private_key/2,
		 open_file/1,
		 file_last_modified/1,
		 is_number/1,
		 is_valid_content_type/1,
		 is_value_field_type/2,
		 is_cpf_valid/1, 
		 is_cnpj_valid/1, 
		 ip_list/0,
		 ip_list/1,
		 is_url_valido/1,
 		 is_email_valido/1, 
 		 is_range_valido/3,
		 is_letter/1,
		 is_letter_lower/1,
		 posix_error_description/1,
		 ldap_attribute_map_to_user_field/1,
		 parse_content_type/1,
		 parse_oauth2_scope/1,
		 parse_ldap_attributes/1,
		 parse_ldap_filter/1,
		 parse_querystring/1,
		 parse_if_modified_since/1,
		 parse_basic_authorization_header/1,
		 parse_result_cache/1,
		 parse_timeout/2,
		 parse_url_service/1,
		 parse_lang/1,
		 parse_name_service/1,
		 parse_name_querystring/1,
		 parse_type_service/1,
		 parse_type_querystring/1,
		 parse_service_service/1,
		 parse_querystring_def/2,
		 parse_file_name_path/3,
		 parse_file_name_path/1,
 		 parse_bool/1,
		 parse_authorization_type/1,
		 parse_bearer_authorization_header/1,
		 parse_tcp_listen_address/2,
		 parse_allowed_address_t/1,
		 parse_allowed_address/1,
		 parse_tcp_port/1,
		 parse_request_querystring/2,
		 parse_range/3,
		 parse_range/4,
		 parse_email/1,
		 parse_ldap_name/1,
		 parse_to_integer/1,
		 match_ip_address/2,
 		 allow_ip_address/2,
		 mask_ipaddress_to_tuple/1,
		 encode_request_cowboy/3,
		 msg_campo_obrigatorio/2, msg_email_invalido/2, mensagens/1,
		 msg_registro_ja_existe/1, msg_registro_ja_existe/2,
		 hashsym_and_params/1,
		 hashsym_and_params/4,
		 hashsym_and_params_id/2,
		 hashsym/1,
		 make_rowid/1,
		 make_rowid/2,
		 make_rowid_id/1,
		 quote/1,
 		 remove_quoted_str/1,
		 remove_ult_backslash_url/1,
		 remove_ult_backslash_url_binary/1,
		 name_case/1,
		 modernize/1,
		 mes_abreviado/1,
		 new_rowid_service/2,
		 json_encode_table2/2,
		 utf8_list_to_string/1,
		 utf8_list_to_binary/1,
		 utf8_binary_to_list/1,
		 normalize_field_utf8/1,
		 utf8_string_win/1,
		 utf8_string_linux/1,
		 criptografia_sha1/1,
		 criptografia_md5/1,
		 criptografia_blowfish/1,
		 head_file/2,
		 replace_all_vars_binary/2,
		 replace_all_vars/2,
		 replace_all_vars_and_custom_variables/2,
		 replace_all_vars_and_custom_variables_binary/2,
		 replace_custom_variables/1,
		 replace_custom_variables_binary/1,
		 replace_config_and_custom_variables_binary/1,
		 replace_config_and_custom_variables/1,
		 to_utf8/1,
		 load_erlang_module/1,
		 mime_type/1,
		 rid_to_string/1,
		 method_to_string/1,
		 decode_http_header/2,
		 decode_http_request/1,
		 tuple_to_maps_with_keys/2,
		 compile_modulo_erlang/2,
		 print_int_map/1,
		 print_str_map/1,
		 parse_user_agent/1,
		 user_agent_atom_to_binary/1,
		 to_lower_and_remove_backslash/1,
		 check_type_email/2,
		 is_email_institucional/2,
		 invoque_service/3,
		 url_mask/1,
		 url_mask_str/1,
		 list_map_to_list_tuple/1,
		 list_tuple_to_list_map/1,
		 format_rest_status/5,
		 os_command/1,
		 os_command/2,
		 integer_to_list_def/2,
		 str_trim/1,
		 binary_to_hex/1,
		 str_contains/2,
		 oauth2_authenticate_rest_server/3,
		 path_writable/1,
		 file_writable/1,
		 ensure_dir_writable/1,
		 file_exists/1,
		 is_production_server/0
		]).

-spec version() -> string().
version() ->
	case application:get_key(ems_bus, vsn) of 
		{ok, Version} -> Version;
		undefined -> "1.0.0"
	end.

-spec server_name() -> string().
server_name() ->
	iolist_to_binary([<<"ems-bus-">>, [case application:get_key(ems_bus, vsn) of 
											{ok, Version} -> list_to_binary(Version);
											undefined -> <<"1.0.0">>
									  end]]).

%% Retorna o hash da url e os parâmetros do request
hashsym_and_params(S) when is_binary(S) -> hashsym_and_params(binary_to_list(S), 1, 0, []);
hashsym_and_params(S) -> hashsym_and_params(S, 1, 0, []).

hashsym_and_params([], _Idx, Hash, Params) -> 
	{Hash, maps:from_list(Params)};
hashsym_and_params([H|[N|_] = L], Idx, Hash, Params) when H == 47 andalso N >= 48 andalso N =< 57 -> 
	{L2, P} = hashsym_and_params_id(L, 0),
	P2 = case Idx of
			1 -> {<<"id">>, P};
			_ -> {list_to_binary("id_" ++ erlang:integer_to_list(Idx)), P}
		 end,
	hashsym_and_params(L2, Idx+1, (Hash + 1) bsl 1, [P2 | Params]);
hashsym_and_params([H|[N|_]], _Idx, _Hash, _Params) when H == 47 andalso N == 45 -> 
	throw(einvalid_id_object_negative);
hashsym_and_params([H|L], Idx, Hash, Params) when H == 47 -> % Ascii /
	hashsym_and_params(L, Idx, Hash, Params);
hashsym_and_params([H|T], Idx, Hash, Params) when (H >= 97 andalso H =< 122)  % Ascii a até z
												 orelse H == 95 % Ascii _
												 orelse (H >= 45 andalso H =< 57) % Ascii - até 9
												 orelse (H >= 64 andalso H =< 90) -> % Ascii @ até Z
	hashsym_and_params(T, Idx, (Hash + H) bsl 1, Params);
hashsym_and_params(_, _, _, _) -> throw(einvalid_url).
												 

hashsym_and_params_id([], P) -> 
	case P > 0 andalso P =< 999999999999999999999 of
		true -> {[], P};
		false -> throw({einvalid_id_object, P})
	end;
hashsym_and_params_id([H|T], P) when H == 47 -> {T, P};
hashsym_and_params_id([H|T], P) when (H >= 48 andalso H =< 57) -> hashsym_and_params_id(T, P * 10 + H - $0);
hashsym_and_params_id(L, _) -> throw({einvalid_id_object, L}).


%% Retorna o hash da url (uso em tempo de execução)
hashsym(S) -> 
	{Hash, _} = hashsym_and_params(S),
	Hash.


%% Retorna o hash da url (uso no carregamento dos catálogos)	
make_rowid(null) -> 0;
make_rowid(undefined) -> 0;
make_rowid(S) when is_binary(S) -> make_rowid(binary_to_list(S), 0);
make_rowid(S) -> make_rowid(S, 0).

make_rowid([], Hash) -> Hash;
make_rowid([H|T], Hash) when H == 47 -> make_rowid(T, Hash);
make_rowid([H|T], Hash) when H == 58 -> make_rowid(make_rowid_id(T), (Hash + 1) bsl 1);
make_rowid([H|T], Hash) -> make_rowid(T, (Hash + H) bsl 1).

make_rowid_id([]) -> [];
make_rowid_id([H|T]) when H == 47 -> T;
make_rowid_id([_|T]) -> make_rowid_id(T).


-spec get_priv_dir_default() -> string().
get_priv_dir_default() ->
	{ok, Path} = file:get_cwd(),
	Path ++ "/priv".

-spec get_priv_dir() -> string().
get_priv_dir() ->
	ems_db:get_param(priv_path, get_priv_dir_default()).

get_www_path() ->
	ems_db:get_param(www_path, filename:join(get_priv_dir_default(), "www")).

get_log_file_path() ->
	ems_db:get_param(log_file_path, filename:join(get_priv_dir_default(), "log")).

get_log_file_archive_path() ->
	ems_db:get_param(log_file_archive_path, filename:join(get_priv_dir_default(), "archive_log")).

	
get_auth_default_scope() ->	
	ems_db:get_param(auth_default_scope, ?AUTH_DEFAULT_SCOPE).
	
get_auth_password_check_between_scope() ->	
	ems_db:get_param(auth_password_check_between_scope, true).
	

-spec get_working_dir() -> string().
get_working_dir() ->
	{ok, Path} = file:get_cwd(),
	Path.

-spec get_home_dir() -> string().
get_home_dir() ->
	{ok, [[Path]]} = init:get_argument(home),
	Path.


-spec sleep(non_neg_integer()) -> true.
sleep(T) ->
    receive
	    after T -> true
    end.


-spec timestamp_str() -> string().
timestamp_str() -> binary_to_list(timestamp_binary()).

-spec timestamp_binary() -> binary().
timestamp_binary() ->
	Timestamp = calendar:local_time(),
	timestamp_binary(Timestamp).
	
-spec timestamp_str(tuple()) -> string().
timestamp_str({{_Ano,_Mes,_Dia},{_Hora,_Min,_Seg}} = Timestamp) ->	binary_to_list(timestamp_binary(Timestamp));
timestamp_str(_) -> "".  

-spec timestamp_binary(tuple()) -> binary().
timestamp_binary({{Ano,Mes,Dia},{Hora,Min,Seg}}) ->
	DiaBin = integer_to_binary(Dia),
	MesBin = integer_to_binary(Mes),
	AnoBin = integer_to_binary(Ano),
	HoraBin = integer_to_binary(Hora),
	MinBin = integer_to_binary(Min),
	SegBin = integer_to_binary(Seg),
	case Seg < 10 of 
		true -> 
			case Min < 10 of 
				true ->
					case Hora < 10 of
						true ->
							case Mes < 10 of
								true -> 
									case Dia < 10 of
										true -> 
											iolist_to_binary([<<"0">>, DiaBin, <<"/0">>, MesBin, <<"/">>, AnoBin, <<" 0">>, HoraBin, <<":0">>, MinBin, <<":0">>, SegBin]);
										false ->
											iolist_to_binary([DiaBin, <<"/0">>, MesBin, <<"/">>, AnoBin, <<" 0">>, HoraBin, <<":0">>, MinBin, <<":0">>, SegBin])
									end;
								false ->
									case Dia < 10 of
										true -> 
											iolist_to_binary([<<"0">>, DiaBin, <<"/">>, MesBin, <<"/">>, AnoBin, <<" 0">>, HoraBin, <<":0">>, MinBin, <<":0">>, SegBin]);
										false ->
											iolist_to_binary([DiaBin, <<"/">>, MesBin, <<"/">>, AnoBin, <<" 0">>, HoraBin, <<":0">>, MinBin, <<":0">>, SegBin])
									end
							end;
						false ->
							case Mes < 10 of
								true -> 
									case Dia < 10 of
										true -> 
											iolist_to_binary([<<"0">>, DiaBin, <<"/0">>, MesBin, <<"/">>, AnoBin, <<" ">>, HoraBin, <<":0">>, MinBin, <<":0">>, SegBin]);
										false ->
											iolist_to_binary([DiaBin, <<"/0">>, MesBin, <<"/">>, AnoBin, <<" ">>, HoraBin, <<":0">>, MinBin, <<":0">>, SegBin])
									end;
								false ->
									case Dia < 10 of
										true -> 
											iolist_to_binary([<<"0">>, DiaBin, <<"/">>, MesBin, <<"/">>, AnoBin, <<" ">>, HoraBin, <<":0">>, MinBin, <<":0">>, SegBin]);
										false ->
											iolist_to_binary([DiaBin, <<"/">>, MesBin, <<"/">>, AnoBin, <<" ">>, HoraBin, <<":0">>, MinBin, <<":0">>, SegBin])
									end
							end
					end;
				false ->
					case Hora < 10 of
						true ->
							case Mes < 10 of
								true -> 
									case Dia < 10 of
										true -> 
											iolist_to_binary([DiaBin, <<"/0">>, MesBin, <<"/">>, AnoBin, <<" 0">>, HoraBin, <<":">>, MinBin, <<":0">>, SegBin]);
										false ->
											iolist_to_binary([<<"0">>, DiaBin, <<"/0">>, MesBin, <<"/">>, AnoBin, <<" 0">>, HoraBin, <<":">>, MinBin, <<":0">>, SegBin])
									end;
								false ->
									case Dia < 10 of
										true -> 
											iolist_to_binary([<<"0">>, DiaBin, <<"/">>, MesBin, <<"/">>, AnoBin, <<" 0">>, HoraBin, <<":">>, MinBin, <<":0">>, SegBin]);
										false ->
											iolist_to_binary([DiaBin, <<"/">>, MesBin, <<"/">>, AnoBin, <<" 0">>, HoraBin, <<":">>, MinBin, <<":0">>, SegBin])
									end
							end;
						false ->
							case Mes < 10 of
								true -> 
									case Dia < 10 of
										true -> 
											iolist_to_binary([<<"0">>, DiaBin, <<"/0">>, MesBin, <<"/">>, AnoBin, <<" ">>, HoraBin, <<":">>, MinBin, <<":0">>, SegBin]);
										false ->
											iolist_to_binary([DiaBin, <<"/0">>, MesBin, <<"/">>, AnoBin, <<" ">>, HoraBin, <<":">>, MinBin, <<":0">>, SegBin])
									end;
								false ->
									case Dia < 10 of
										true -> 
											iolist_to_binary([<<"0">>, DiaBin, <<"/">>, MesBin, <<"/">>, AnoBin, <<" ">>, HoraBin, <<":">>, MinBin, <<":0">>, SegBin]);
										false ->
											iolist_to_binary([DiaBin, <<"/">>, MesBin, <<"/">>, AnoBin, <<" ">>, HoraBin, <<":">>, MinBin, <<":0">>, SegBin])
									end
							end
					end
			end;
		false ->
			case Min < 10 of 
				true ->
					case Hora < 10 of
						true ->
							case Mes < 10 of
								true -> 
									case Dia < 10 of
										true -> 
											iolist_to_binary([<<"0">>, DiaBin, <<"/0">>, MesBin, <<"/">>, AnoBin, <<" 0">>, HoraBin, <<":0">>, MinBin, <<":">>, SegBin]);
										false ->
											iolist_to_binary([DiaBin, <<"/0">>, MesBin, <<"/">>, AnoBin, <<" 0">>, HoraBin, <<":0">>, MinBin, <<":">>, SegBin])
									end;
								false ->
									case Dia < 10 of
										true -> 
											iolist_to_binary([<<"0">>, DiaBin, <<"/">>, MesBin, <<"/">>, AnoBin, <<" 0">>, HoraBin, <<":0">>, MinBin, <<":">>, SegBin]);
										false ->
											iolist_to_binary([DiaBin, <<"/">>, MesBin, <<"/">>, AnoBin, <<" 0">>, HoraBin, <<":0">>, MinBin, <<":">>, SegBin])
									end
							end;
						false ->
							case Mes < 10 of
								true -> 
									case Dia < 10 of
										true -> 
											iolist_to_binary([<<"0">>, DiaBin, <<"/0">>, MesBin, <<"/">>, AnoBin, <<" ">>, HoraBin, <<":0">>, MinBin, <<":">>, SegBin]);
										false ->
											iolist_to_binary([DiaBin, <<"/0">>, MesBin, <<"/">>, AnoBin, <<" ">>, HoraBin, <<":0">>, MinBin, <<":">>, SegBin])
									end;
								false ->
									case Dia < 10 of
										true -> 
											iolist_to_binary([<<"0">>, DiaBin, <<"/">>, MesBin, <<"/">>, AnoBin, <<" ">>, HoraBin, <<":0">>, MinBin, <<":">>, SegBin]);
										false ->
											iolist_to_binary([DiaBin, <<"/">>, MesBin, <<"/">>, AnoBin, <<" ">>, HoraBin, <<":0">>, MinBin, <<":">>, SegBin])
									end
							end
					end;
				false ->
					case Hora < 10 of
						true ->
							case Mes < 10 of
								true -> 
									case Dia < 10 of
										true -> 
											iolist_to_binary([<<"0">>, DiaBin, <<"/0">>, MesBin, <<"/">>, AnoBin, <<" 0">>, HoraBin, <<":">>, MinBin, <<":">>, SegBin]);
										false ->
											iolist_to_binary([DiaBin, <<"/0">>, MesBin, <<"/">>, AnoBin, <<" 0">>, HoraBin, <<":">>, MinBin, <<":">>, SegBin])
									end;
								false ->
									case Dia < 10 of
										true -> 
											iolist_to_binary([<<"0">>, DiaBin, <<"/">>, MesBin, <<"/">>, AnoBin, <<" 0">>, HoraBin, <<":">>, MinBin, <<":">>, SegBin]);
										false ->
											iolist_to_binary([DiaBin, <<"/">>, MesBin, <<"/">>, AnoBin, <<" 0">>, HoraBin, <<":">>, MinBin, <<":">>, SegBin])
									end
							end;
						false ->
							case Mes < 10 of
								true -> 
									case Dia < 10 of
										true -> 
											iolist_to_binary([<<"0">>, DiaBin, <<"/0">>, MesBin, <<"/">>, AnoBin, <<" ">>, HoraBin, <<":">>, MinBin, <<":">>, SegBin]);
										false ->
											iolist_to_binary([DiaBin, <<"/0">>, MesBin, <<"/">>, AnoBin, <<" ">>, HoraBin, <<":">>, MinBin, <<":">>, SegBin])
									end;
								false ->
									case Dia < 10 of
										true -> 
											iolist_to_binary([<<"0">>, DiaBin, <<"/">>, MesBin, <<"/">>, AnoBin, <<" ">>, HoraBin, <<":">>, MinBin, <<":">>, SegBin]);
										false ->
											iolist_to_binary([DiaBin, <<"/">>, MesBin, <<"/">>, AnoBin, <<" ">>, HoraBin, <<":">>, MinBin, <<":">>, SegBin])
									end
							end
					end
			end
	end;
timestamp_binary(_) ->  <<>>.


-spec date_to_string(tuple()) -> string().
date_to_string({{Ano,Mes,Dia},{_Hora,_Min,_Seg}}) ->
    lists:flatten(io_lib:format("~2..0B/~2..0B/~4..0B", [Dia, Mes, Ano]));
date_to_string(_) -> "".    

-spec date_to_binary(tuple()) -> binary().
date_to_binary({{Ano,Mes,Dia},{_Hora,_Min,_Seg}}) ->
    iolist_to_binary(io_lib:format("~2..0B/~2..0B/~4..0B", [Dia, Mes, Ano]));
date_to_binary(_) -> <<>>.
    
date_diff_seconds(Date1, Date2) ->    
	calendar:datetime_to_gregorian_seconds(Date1) - calendar:datetime_to_gregorian_seconds(Date2).    
    
-spec time_to_binary(tuple()) -> binary().
time_to_binary({{_Ano,_Mes,_Dia},{Hora,Min,Seg}}) ->
    iolist_to_binary(io_lib:format("~2..0B:~2..0B:~2..0B", [Hora, Min, Seg]));
time_to_binary(_) -> <<>>.


tuple_to_binlist(T) ->
	L = tuple_to_list(T),
	list_to_binlist(L).

-spec list_to_binlist(list(string())) -> list(binary()).
list_to_binlist([]) -> [];
list_to_binlist(<<>>) -> [];
list_to_binlist(<<V/binary>>) -> [V];
list_to_binlist(Value) -> list_to_binlist(Value, []).
	
list_to_binlist([], Result) -> lists:reverse(Result);	
list_to_binlist([H|T], Result) -> 	
	list_to_binlist(T, [item_to_binary(H) | Result]).

-spec binlist_to_list(list(binary())) -> list(string()).
binlist_to_list(<<>>) -> [];
binlist_to_list([]) -> [];
binlist_to_list(Value) -> binlist_to_list(Value, []).

binlist_to_list([], Result) -> lists:reverse(Result);
binlist_to_list([H|T], Result) ->
	binlist_to_list(T, [binary_to_list(H)|Result]).


join_binlist([], _) -> "";
join_binlist(BinList, Str) -> string:join(binlist_to_list(BinList), Str).

-spec item_to_binary(any()) -> binary().
item_to_binary(undefined) -> undefined;
item_to_binary(null) -> undefined;
item_to_binary([]) -> <<>>;
item_to_binary(<<I/binary>>) -> I;
item_to_binary(T) when is_tuple(T) -> 
	tuple_to_binlist(T);
item_to_binary(L) when is_list(L) -> 
	case io_lib:printable_list(L) of
		true -> 
			L2 = [case Ch of 
					34 -> "\\\""; 
					_ -> Ch 
				  end || Ch <- L],
			iolist_to_binary(L2);
		false -> list_to_binlist(L)
	end;
item_to_binary(I) when is_integer(I) -> I;
item_to_binary(I) when is_float(I) -> I;
item_to_binary(I) when is_atom(I) -> 
	[I2] = io_lib:format("~p", [I]),
	iolist_to_binary(I2);
item_to_binary(I) when is_map(I) -> I;
item_to_binary(I) ->
	iolist_to_binary(I).
	
	

%% @doc Converte dados Erlang para JSON
json_encode([]) -> <<"null">>;
json_encode(T) when is_tuple(T) ->
	L = tuple_to_binlist(T),
	?JSON_LIB:encode(L);
json_encode(L) when is_list(L) ->
	case io_lib:printable_list(L) of
		true -> L2 = iolist_to_binary(L);
		false -> L2 = list_to_binlist(L)
	end,
	?JSON_LIB:encode(L2);
json_encode(Value)-> ?JSON_LIB:encode(Value).


json_decode_as_map_file(Filename) ->
	case file:read_file(Filename) of
		{ok, JSON} -> json_decode_as_map(JSON);
		{error, enoent} -> {error, einvalid_json_filename}
	end.


%% @doc Converte um JSON para dados Erlang usando map
json_decode_as_map(JSON) ->
	try
		Dados1 = binary_to_list(JSON),
		Dados2 = lists:flatten(re:replace(Dados1, "[\t\r\n]", "", [global, {return,list}])),
		Dados3 = list_to_binary(Dados2),
		Result = ?JSON_LIB:decode(Dados3, [return_maps]),
		{ok, Result}
	catch
		_Exception:Reason -> {error, Reason}
	end.

%% @doc Converte um JSON para dados Erlang
json_decode(JSON) ->
	try
		JSON2 = case check_encoding_bin(JSON) of
			latin1 -> unicode:characters_to_binary(binary_to_list(JSON), latin1, utf8);
			utf8 -> JSON;
			_ -> erlang:raise(einvalid_json_encoding)
		end,
		T = ?JSON_LIB:decode(JSON2),
		{ok, element(1, T)}
	catch
		_Exception:Reason -> {error, Reason}
	end.
	
%% @doc Retorna o primeiro item da lista ou vazio
-spec hd_or_empty(list()) -> any().
hd_or_empty(List) when length(List) > 0 -> 
	hd(List);
hd_or_empty(_) -> [].

%% @doc Retorna a string com aspas
quote(Str) -> lists:flatten([$", Str, $"]).

-spec remove_quoted_str(string()) -> string().
remove_quoted_str("\"" ++ Str) -> 
	case lists:reverse(Str) of
		"\"" ++ Str2 -> lists:reverse(Str2);
		_ -> Str
	end;
remove_quoted_str(Str) -> Str.


%% @doc Boolean indicando se DateTime ocorreu no período (min, hour, day, week, year)
no_periodo(DateTime, Periodo) ->
	S1 = calendar:datetime_to_gregorian_seconds(DateTime),
	S2 = calendar:datetime_to_gregorian_seconds(calendar:local_time()),
	case Periodo of
		"min"   ->  (S2 - S1) =< 60;
		"hour"  ->  (S2 - S1) =< 3600;
		"day"   ->  (S2 - S1) =< 86400;
		"week"  ->  (S2 - S1) =< 604800;
		"month" ->  (S2 - S1) =< 2629800;
		"year"  ->  (S2 - S1) =< 31557600;
		_ -> erlang:error(badarg)
	end.


%% @doc Obtém a hora atual em milisegundos
-spec get_milliseconds() -> integer().
get_milliseconds() ->
	% Fórmula anterior:
		% {Mega, Sec, Micro} = erlang:timestamp(),
		% (Mega*1000000 + Sec)*1000 + round(Micro/1000).
	trunc(erlang:system_time() / 1.0e6).
	
%% @doc Remove o último backslash da Url
-spec remove_ult_backslash_url(string()) -> string().
remove_ult_backslash_url("/") -> "/";
remove_ult_backslash_url(Value) ->
	case lists:reverse(Value) of
		"/" ++ T -> lists:reverse(T);
		_ -> Value
	end.

remove_ult_backslash_url_binary(Url) -> list_to_binary(remove_ult_backslash_url(binary_to_list(Url))).


%% @doc Função name case
name_case([H|T]) when H >= $a, H =< $z -> 
	[H + ($A - $a) | T];
name_case(outros) -> outros.


%% @doc Primeiro caracter de cada palabra em caixa alta
modernize([H|T]) -> 
	Tokens = string:tokens([H|T], " "),
	Lista = [name_case(S) || S <- Tokens],
	string:join(Lista, " ").


%% @doc Retorna o mês por extenso a partir do ordinal
mes_extenso(1) -> "Janeiro";
mes_extenso(2) -> "Fevereiro";
mes_extenso(3) -> "Março";
mes_extenso(4) -> "Abril";
mes_extenso(5) -> "Maio";
mes_extenso(6) -> "Junho";
mes_extenso(7) -> "Julho";
mes_extenso(8) -> "Agosto";
mes_extenso(9) -> "Setembro";
mes_extenso(10) -> "Outubro";
mes_extenso(11) -> "Novembro";
mes_extenso(12) -> "Dezembro";
mes_extenso(_) -> erlang:error(badarg).

mes_abreviado(1) -> "jan";
mes_abreviado(2) -> "fev";
mes_abreviado(3) -> "mar";
mes_abreviado(4) -> "abr";
mes_abreviado(5) -> "maio";
mes_abreviado(6) -> "jun";
mes_abreviado(7) -> "jul";
mes_abreviado(8) -> "ago";
mes_abreviado(9) -> "set";
mes_abreviado(10) -> "out";
mes_abreviado(11) -> "nov";
mes_abreviado(12) -> "dez";
mes_abreviado(_) -> erlang:error(badarg).



%% @doc Retorna um ets a partir de uma lista
list_to_ets(List, Name, Options) ->
	Ets = ets:new(Name, Options),
	lists:foreach(fun(X) -> ets:insert(Ets, X) end, List),
	Ets.
	
profile() ->
	fprof:trace([stop]),
	fprof:profile(),
	fprof:analyse([totals, {dest, "fprof.txt"}]).

new_rowid_service(<<Url/binary>>, <<Type/binary>>) ->	
	[PrefixUrl|Url2] = binary_to_list(Url),
	case PrefixUrl of
		$^ -> iolist_to_binary([Type, <<"#">>, list_to_binary(Url2)]);
		_  -> iolist_to_binary([Type, <<"#">>, Url])
	end;

new_rowid_service(Url, Type) ->	
	[PrefixUrl|Url2] = Url,
	case PrefixUrl of
		$^ -> iolist_to_binary([Type, <<"#">>, Url2]);
		_  -> iolist_to_binary([Type, <<"#">>, Url])
	end.

make_rowid_from_url(<<Url/binary>>, <<Type/binary>>) ->	
	make_rowid_from_url(binary_to_list(Url), binary_to_list(Type));

make_rowid_from_url(Url, Type) ->	
	Ret1 = parse_url(Url),
	Ret2 = lists:map(fun({U, _}) -> U end, Ret1),
	Ret3 = string:join(Ret2, "/"),
	iolist_to_binary([Type, <<"#/">>, Ret3]).

get_rowid_and_params_from_url(<<Url/binary>>, <<Type/binary>>) ->	
	get_rowid_and_params_from_url(binary_to_list(Url), binary_to_list(Type));

get_rowid_and_params_from_url(Url, Type) ->
	UrlParsed = parse_url(Url),
	UrlParsed2 = lists:map(fun({U, _}) -> U end, UrlParsed),
	UrlParsed3 = string:join(UrlParsed2, "/"),
	Rowid = iolist_to_binary([Type, <<"#/">>, UrlParsed3]),
	ParamsUrl = [{list_to_binary(U), P} || {[_|U], P} <- UrlParsed, P /= [] ],
	ParamsUrlMap = maps:from_list(ParamsUrl),
	{Rowid, ParamsUrlMap}.
	

get_params_from_url(Url) -> [X || {_, P} = X <- parse_url(Url), P /= [] ].


parse_url(Url) ->	
	Url2 = string:tokens(Url, "/"),
	try
		parse_url_tail(Url2, 1, [])
	catch error:badarg ->
		erlang:error(einvalid_id_object)
	end.

parse_url_tail([], _, L) -> lists:reverse(L);
	
parse_url_tail([H|T], SeqId, L) ->	
    {UrlParte, Param, SeqId2} = parse_parte_url(H, SeqId),
	parse_url_tail(T, SeqId2, [{UrlParte, Param} | L]).
	
parse_parte_url([H|_] = UrlParte, SeqId) ->
	if
		H >= 49 andalso H =< 57 ->
			SeqId_ = case SeqId of
				1 -> ":id";
				_ -> ":id_" ++ integer_to_list(SeqId)
			end,
			{SeqId_, list_to_integer(UrlParte), SeqId+1};
		H =:= 45 ->
			erlang:error(einvalid_id_object);
		true -> {UrlParte, [], SeqId}
	end.


string_is_integer(S) ->
    try
        _ = list_to_integer(S),
        true
    catch error:badarg ->
        false
    end.

node_is_live(Node) -> 
	case net_adm:ping(Node) of
		pong -> 1;
		_ -> 0
	end.

% Retorna somente a parte do name do node sem a parte do hostname após @
get_node_name() -> hd(string:tokens(atom_to_list(node()), "@")).

json_field_format_table(null) -> [<<"\""/utf8>>, <<"\""/utf8>>];
json_field_format_table(V) when is_float(V) -> list_to_binary(mochinum:digits(V));
json_field_format_table(V) when is_integer(V) -> list_to_binary(mochinum:digits(V));
json_field_format_table(V) when is_boolean(V) -> boolean_to_binary(V);
json_field_format_table(V) when is_binary(V) -> [<<"\""/utf8>>, ?UTF8_STRING(V), <<"\""/utf8>>];
json_field_format_table(V) when is_list(V) -> [<<"\""/utf8>>, ?UTF8_STRING(list_to_binary(V)), <<"\""/utf8>>];
json_field_format_table(Data = {{_,_,_},{_,_,_}}) -> [<<"\""/utf8>>, list_to_binary(date_to_string(Data)), <<"\""/utf8>>];
json_field_format_table(V) -> throw({error, einvalid_value, validation, "Could not serialize " ++ V}).


json_encode_record(_, [], true, RecordJson) -> 	
	[<<"{"/utf8>>, lists:reverse(RecordJson), <<"},"/utf8>>];
json_encode_record(_, [], false, RecordJson) -> 		
	[<<"{"/utf8>>, lists:reverse(RecordJson), <<"}"/utf8>>];
json_encode_record([F|FTail], [V|VTail], HasMoreRecords, RecordJson) -> 	
	Field = case VTail of
		[] -> iolist_to_binary([<<"\""/utf8>>, F, <<"\""/utf8>>, <<":"/utf8>>, json_field_format_table(V)]);
		_ -> 
			iolist_to_binary([<<"\""/utf8>>, F, <<"\""/utf8>>, <<":"/utf8>>, json_field_format_table(V), <<","/utf8>>])
	end,
	json_encode_record(FTail, VTail, HasMoreRecords, [Field | RecordJson]).


json_encode_table(_, [], TableJson) -> 
	iolist_to_binary([<<"["/utf8>>, lists:reverse(TableJson), <<"]"/utf8>>]);
json_encode_table(Fields, [R|RTail], TableJson) -> 
	Values = tuple_to_list(R),
	HasMoreRecords = RTail =/= [],
	R2 = json_encode_record(Fields, Values, HasMoreRecords, []),
	json_encode_table(Fields, RTail, [R2 | TableJson]).

-spec json_encode_table(list(binary()), list(binary())) -> string().
json_encode_table(Fields, Records) -> 
	Result = json_encode_table(Fields, Records, []),
	Result.

json_encode_table2(Fields, Records) ->
	Objects = lists:map(fun(T) -> 
							   lists:zipwith(fun(Fld, Value) -> 
													io_lib:format(<<"\"~s\":~p"/utf8>>, [Fld, json_field_format_table(Value)]) 
											 end,  Fields, tuple_to_list(T))
					end, Records), 
	Objects2 = lists:map(fun(Obj) -> 
									[<<"{"/utf8>>, string:join(Obj, ", "), <<"}"/utf8>>] 
						 end, Objects),
	Objects3 = string:join(Objects2, ", "),
	Result = unicode:characters_to_binary([<<"["/utf8>>, Objects3, <<"]"/utf8>>], utf8),
	Result.


utf8_list_to_string(null) -> "";
utf8_list_to_string(Value) ->
	try
		case check_encoding_bin(list_to_binary(Value)) of
			utf8 -> unicode:characters_to_list(mochiutf8:valid_utf8_bytes(list_to_binary(Value)), utf8);
			latin1 -> unicode:characters_to_list(Value, utf8)
		end
	catch
		_Exception:Reason -> 
			io:format("utf8_list_to_string error ~p with value ~p\n", [Reason, Value]), 
			<<>>
	end.
	

utf8_list_to_binary(Value) -> binary_to_list(utf8_list_to_string(Value)).

utf8_binary_to_list(Value) ->
	case unicode:characters_to_list(Value) of
		{error, _, _ } -> Value;
		Value2 -> Value2
	end.


date_add_minute(Timestamp, Minutes) ->
    calendar:gregorian_seconds_to_datetime(calendar:datetime_to_gregorian_seconds(Timestamp) + (Minutes * 60)).

date_dec_minute(Timestamp, Minutes) ->
    calendar:gregorian_seconds_to_datetime(calendar:datetime_to_gregorian_seconds(Timestamp) - (Minutes * 60)).

date_add_second(Timestamp, Seconds) ->
    calendar:gregorian_seconds_to_datetime(calendar:datetime_to_gregorian_seconds(Timestamp) + Seconds).

date_dec_second(Timestamp, Seconds) ->
    calendar:gregorian_seconds_to_datetime(calendar:datetime_to_gregorian_seconds(Timestamp) - Seconds).

date_add_day(Timestamp, Days) ->
    calendar:gregorian_seconds_to_datetime(calendar:datetime_to_gregorian_seconds(Timestamp) + (Days * 86400)).

boolean_to_binary(true) -> <<"true"/utf8>>;
boolean_to_binary(1) -> <<"true"/utf8>>;
boolean_to_binary(<<"true"/utf8>>) -> <<"true"/utf8>>;
boolean_to_binary(<<"1"/utf8>>) -> <<"true"/utf8>>;
boolean_to_binary(_) -> <<"false"/utf8>>.


value_to_boolean(true) -> true;
value_to_boolean(1) -> true;
value_to_boolean(<<"true"/utf8>>) -> true;
value_to_boolean(<<"1"/utf8>>) -> true;
value_to_boolean("1") -> true;
value_to_boolean("true") -> true;
value_to_boolean(_) -> false.


%%melhorar este método para conversão para utf8
utf8_string_win(<<>>) -> <<""/utf8>>;
utf8_string_win("") -> <<""/utf8>>;
utf8_string_win(undefined) -> <<""/utf8>>;
utf8_string_win(null) -> <<""/utf8>>;
utf8_string_win(Text) when is_list(Text) -> 
	utf8_string_win(list_to_binary(Text));
utf8_string_win(Text) when erlang:is_number(Text) -> integer_to_binary(Text);
utf8_string_win(Text) ->
	try
		case check_encoding_bin(Text) of
			utf8 -> normalize_field_utf8(Text);
			latin1 -> normalize_field_utf8(Text);
			_ -> Text
		end
	catch
		_Exception:Reason -> 
			?DEBUG("utf8_string_win convert ~p error: ~p\n", [Text, Reason]),
			Text
	end.


check_encoding_bin(Bin) when is_binary(Bin) ->
    case unicode:characters_to_binary(Bin,utf8,utf8) of
	Bin ->
	    utf8;
	_ ->
	    latin1
    end.

% Prepara um campo texto para o formato JSON UTF 8
%normalize_field_utf8("") ->	"";
%normalize_field_utf8(<<>>) -> "";
%normalize_field_utf8(V) when is_binary(V) -> normalize_field_utf8(unicode:characters_to_list(V));
%normalize_field_utf8(V) -> 
%	Text = case string:strip(V) of
%				[] -> "";
%				V2 -> [case Ch of 
%							34 -> "\\\""; 
%							_ -> Ch 
%					  end || Ch <- V2, Ch > 31]
%			end,
%	case unicode:characters_to_binary(Text, utf8) of
%		{error, _} -> 
%			unicode:characters_to_binary(Text, latin1);
%		Result -> Result
%	end.

% Prepara um campo texto para o formato JSON UTF 8
normalize_field_utf8("") ->	"";
normalize_field_utf8(<<>>) -> "";
normalize_field_utf8(V) when is_binary(V) -> normalize_field_utf8(binary_to_list(V));
normalize_field_utf8(V) -> 
	Text = case string:strip(V) of
				[] -> "";
				V2 -> [case Ch of 
							34 -> "\\\""; 
							_ -> Ch 
					  end || Ch <- V2, Ch > 31]
			end,
	unicode:characters_to_binary(Text, utf8).

%utf8_string_linux(<<>>) -> <<""/utf8>>;
%utf8_string_linux("") -> <<""/utf8>>;
%utf8_string_linux(undefined) -> <<""/utf8>>;
%utf8_string_linux(null) -> <<""/utf8>>;
%utf8_string_linux(Text) when is_list(Text) -> 
%	utf8_string_linux(list_to_binary(Text));
%utf8_string_linux(Text) when erlang:is_number(Text) -> integer_to_binary(Text);
%utf8_string_linux(Text) ->
%	try
%		normalize_field_utf8(Text)
%	catch
%		_Exception:_Reason -> 
%			%Já está normalizado
%			Text
%	end.


utf8_string_linux(<<>>) -> <<""/utf8>>;
utf8_string_linux("") -> <<""/utf8>>;
utf8_string_linux(undefined) -> <<""/utf8>>;
utf8_string_linux(null) -> <<""/utf8>>;
utf8_string_linux(Text) when is_list(Text) -> 
	utf8_string_linux(list_to_binary(Text));
utf8_string_linux(Text) when erlang:is_number(Text) -> integer_to_binary(Text);
utf8_string_linux(Text) ->
	try
		normalize_field_utf8(Text)
	catch
		_Exception:Reason -> 
			?DEBUG("utf8_string_linux convert ~p error: ~p\n", [Text, Reason]),
			normalize_field_utf8(Text)
	end.
	

-spec read_file_as_map(Filename :: string()) -> map().
read_file_as_map(Filename) -> 	
	case file:read_file(Filename) of
		{ok, Arq} -> 
			json_decode_as_map(Arq);
		Error -> Error
	end.


read_file_as_list_add_carriage_return([], Result) -> lists:reverse(Result);
read_file_as_list_add_carriage_return([H|T], Result) ->	
	Result2 = [<<"\n">> | Result],
	Result3 = [H | Result2],
	read_file_as_list_add_carriage_return(T, Result3).


-spec read_file_as_list(string()) -> list().
read_file_as_list(Filename) ->
	{ok, Data} = file:read_file(Filename),
	List = binary:split(Data, [<<"\n">>], [global]),
	read_file_as_list_add_carriage_return(List, []).
	

-spec head_file(string(), non_neg_integer()) -> list().
head_file(Filename, N) ->
	L = read_file_as_list(Filename),
	{ok, lists:sublist(L, (N*2))}.

-spec tail_file(string(), non_neg_integer()) -> list().
tail_file(Filename, N) ->
	L = read_file_as_list(Filename),
	Len = length(L),
	case Len > N of 	
		true ->	
			case Len-(N*2) > 0 of
				true -> {ok, lists:nthtail(Len-(N*2), L)};
				false -> {ok, lists:nthtail(Len-N, L)}
			end;
		false -> 
			{ok, L}
	end.


-spec replace(string(), string(), string()) -> string().
replace(Subject, Var, VarToReplace) -> 
	re:replace(Subject, Var, VarToReplace, [global, {return, list}]).

-spec replace_all(string(), list(tuple())) -> string().
replace_all(Subject, []) -> Subject;
replace_all(Subject, [{Key, Value}|VarTail]) -> 
	NewSubject = replace(Subject, Key, Value),
	replace_all(NewSubject, VarTail).


-spec replace_all_vars_binary(string() | binary(), list(tuple())) -> binary().
replace_all_vars_binary(<<>>, _) -> <<>>;
replace_all_vars_binary(undefined, _) -> undefined;
replace_all_vars_binary(Subject, Vargs) -> 
	list_to_binary(replace_all_vars(Subject, Vargs)).


-spec replace_all_vars_and_custom_variables_binary(string() | binary(), list(tuple())) -> binary().
replace_all_vars_and_custom_variables_binary(<<>>, _) -> <<>>;
replace_all_vars_and_custom_variables_binary(undefined, _) -> undefined;
replace_all_vars_and_custom_variables_binary(Subject, Vargs) -> 
	list_to_binary(replace_all_vars_and_custom_variables(Subject, Vargs)).


-spec replace_all_vars_and_custom_variables(string() | binary(), list(tuple())) -> string().
replace_all_vars_and_custom_variables(Subject, Vargs) -> 
	CustomVariables = ems_db:get_param(custom_variables),
	Result = replace_all_vars(Subject, Vargs),
	ems_util:replace_all_vars(Result, CustomVariables).


-spec replace_custom_variables_binary(string() | binary()) -> binary().
replace_custom_variables_binary(Str) -> 
	CustomVariables = ems_db:get_param(custom_variables),
	list_to_binary(ems_util:replace_all_vars(Str, CustomVariables)).


-spec replace_custom_variables(string() | binary()) -> string().
replace_custom_variables(Str) -> 
	CustomVariables = ems_db:get_param(custom_variables),
	ems_util:replace_all_vars(Str, CustomVariables).


-spec replace_config_and_custom_variables_binary(string() | binary()) -> binary().
replace_config_and_custom_variables_binary(Str) -> 
	list_to_binary(replace_config_and_custom_variables(Str)).


-spec replace_config_and_custom_variables(string() | binary()) -> string().
replace_config_and_custom_variables(Str) -> 
	Conf = ems_config:getConfig(),
	Result = ems_util:replace_all_vars_and_custom_variables(Str, 
		[{<<"HOSTNAME">>, binary_to_list(Conf#config.ems_hostname)},
		 {<<"JAVA_HOME">>, Conf#config.java_home},
		 {<<"JAVA_THREAD_POOL">>, Conf#config.java_thread_pool},
		 {<<"JAVA_JAR_PATH">>, Conf#config.java_jar_path},
		 {<<"REST_BASE_URL">>, binary_to_list(Conf#config.rest_base_url)},
		 {<<"REST_ENVIRONMENT">>, Conf#config.rest_environment},
		 {<<"REST_USER">>, Conf#config.rest_user},
		 {<<"REST_PASSWD">>, Conf#config.rest_passwd},
		 {<<"LDAP_URL">>, Conf#config.ldap_url},
		 {<<"LDAP_ADMIN">>, Conf#config.ldap_admin},
		 {<<"LDAP_PASSWD">>, Conf#config.ldap_password_admin},
		 {<<"SMTP_FROM">>, Conf#config.smtp_from},
		 {<<"SMTP_PASSWD">>, Conf#config.smtp_passwd},
		 {<<"SMTP_PORT">>, Conf#config.smtp_port},
		 {<<"SMTP_MAIL">>, Conf#config.smtp_mail},
		 {<<"PRIV_PATH">>, ?PRIV_PATH}
		]), 
	Result.


-spec replace_all_vars(string() | binary(), list(tuple())) -> string().
replace_all_vars(<<>>, _) -> "";
replace_all_vars(undefined, _) -> undefined;
replace_all_vars(Subject, Vargs) -> 
	SubjectStr = case is_binary(Subject) of
					true -> binary_to_list(Subject);
					false -> Subject
				 end,
	replace_all_vars_(SubjectStr, Vargs).

-spec replace_all_vars_(string(), list(tuple())) -> string().
replace_all_vars_(Subject, []) -> Subject;
replace_all_vars_(Subject, [{Key, Value}|VarTail]) -> 
	KeyStr = case is_binary(Key) of
				true -> binary_to_list(Key);
				false -> Key
			 end,
	ValueStr = case is_binary(Value) of
					true -> binary_to_list(Value);
					false -> 
						case is_integer(Value) of
							true -> integer_to_list(Value);
							false -> Value
						end
			   end,
	NewSubject = replace(Subject, "{{.?"++ string:to_upper(KeyStr) ++ ".?}}", ValueStr),
	NewSubject2 = replace(NewSubject, "{{.?"++ string:to_lower(KeyStr) ++ ".?}}", ValueStr),
	replace_all_vars_(NewSubject2, VarTail).


replace_vars_with(Subject, Value) -> re:replace(Subject, "{{.+}}", Value, [global, {return, list}]).


-spec parse_oauth2_scope(binary()) -> list(atom()).
parse_oauth2_scope(<<>>) -> ?CLIENT_DEFAULT_SCOPE;
parse_oauth2_scope(undefined) -> ?CLIENT_DEFAULT_SCOPE;
parse_oauth2_scope(ScopeBin) ->
	try
		Result0 = list_to_atomlist_with_trim(string:tokens(binary_to_list(ScopeBin), ",")),
		% Adiciona o user_fs no fim da lista pois é obrigatório
		case lists:member(user_fs, Result0) of
			true -> Result0;
			false -> Result0 ++ [user_fs]
		end
	catch
		_:_ -> throw({error, einvalid_oauth2_scope})
	end.


-spec parse_file_name_path(string() | binary()) -> string().
parse_file_name_path(Path) ->
	parse_file_name_path(Path, [], undefined).

% Process the path "~" and "." wildcards and variable path. Return path
-spec parse_file_name_path(string() | binary(), list(tuple()) | undefined, binary() | undefined) -> string().
parse_file_name_path(undefined, _, _) -> <<>>;
parse_file_name_path(<<"undefined">>, _, _) -> <<>>;
parse_file_name_path(<<>>, _, _) -> <<>>;
parse_file_name_path("", _, _) -> <<>>;
parse_file_name_path(Path, StaticFilePathList, RootPath) when is_binary(Path) ->
	parse_file_name_path(binary_to_list(Path), StaticFilePathList, RootPath);
parse_file_name_path(Path, StaticFilePathList, RootPath) ->
	Ch = string:substr(Path, 1, 1),
	Ch2 = string:substr(Path, 2, 1),
	case Ch =:= "/" orelse (is_letter(Ch) andalso Ch2 =:= ":")   of
		true -> remove_ult_backslash_url(Path);  
		false ->
			case Ch == "\~" of
				true -> replace(Path, "\~", get_home_dir());
				_ -> 
					case Ch == "." of
						true -> 
							case RootPath of
								undefined -> remove_ult_backslash_url(string:substr(Path, 3));
								_ -> remove_ult_backslash_url(remove_ult_backslash_url(RootPath) ++ "/" ++ string:substr(Path, 3))
							end;
						false -> 
							Path2 = replace_all_vars_and_custom_variables(Path, StaticFilePathList),
							% after process variables, check ~ or . wildcards
							case string:substr(Path2, 1, 1) == "\~" of
								true -> replace(Path2, "\~", get_home_dir());
								_ -> 
									case Ch == "." of
										true -> 
											case RootPath of
												undefined -> remove_ult_backslash_url(string:substr(Path2, 3));
												_ -> remove_ult_backslash_url(remove_ult_backslash_url(RootPath) ++ "/" ++ string:substr(Path2, 3))
											end;
										false ->  
											case RootPath of
												undefined -> remove_ult_backslash_url(Path2);
												<<>> -> remove_ult_backslash_url(Path2);
												_ -> remove_ult_backslash_url(remove_ult_backslash_url(RootPath) ++ "/" ++ Path2)
											end
									end
							end
					end
			end
	end.


read_file_as_string(Filename) -> 	
	case file:read_file(Filename) of
		{ok, Arq} -> Arq;
		Error -> throw(Error)
	end.
	

encrypt_public_key(PlainText, PublicKey) ->
	[ RSAEntry2 ] = public_key:pem_decode(PublicKey),
	PubKey = public_key:pem_entry_decode( RSAEntry2 ),
	public_key:encrypt_public(PlainText, PubKey).
	
decrypt_private_key(CryptText,PrivateKey) ->
    [ RSAEntry2 ] = public_key:pem_decode(PrivateKey),
	PrivKey = public_key:pem_entry_decode( RSAEntry2 ),
	Result =  public_key:decrypt_private(CryptText, PrivKey ),
	Result.
   

open_file(FilePath) ->
   {ok, PemBin2 } = file:read_file(FilePath),
    PemBin2.

-spec file_last_modified(string()) -> tuple().
file_last_modified(FilePath) ->
	case file:read_file_info(FilePath, [{time, universal}]) of
		{ok, {file_info, _FSize, _Type, _Access, _ATime, MTime, _CTime, _Mode,_,_,_,_,_,_}} -> MTime;
		Error -> Error
	end.
		

%% Converte arquivo latin1 para utf8 formatando os unicodes
%% Esta função está desconfigurando os arquivos no formato utf8	
to_utf8(Filename) ->
	try
		{ok, File} = file:open(Filename, [read,binary]),
		Size = filelib:file_size(Filename),
		{ok, Device} = file:read(File,Size),
		{Type, _Bytes} = unicode:bom_to_encoding(Device),
		case Type of
			utf8 -> Device;	
			_ -> unicode:characters_to_binary(Device, latin1, utf8)
		end,
		{ok, Device}
	catch
		_Exception:Reason -> {error, Reason}
	end.

-spec is_letter(string()) -> boolean().
is_letter(V) ->
	is_letter_lower(string:to_lower(V)).
is_letter_lower("c") -> true;
is_letter_lower("d") -> true;
is_letter_lower("e") -> true;
is_letter_lower("f") -> true;
is_letter_lower("g") -> true;
is_letter_lower("h") -> true;
is_letter_lower("i") -> true;
is_letter_lower("j") -> true;
is_letter_lower("k") -> true;
is_letter_lower("l") -> true;
is_letter_lower("m") -> true;
is_letter_lower("n") -> true;
is_letter_lower("o") -> true;
is_letter_lower("p") -> true;
is_letter_lower("q") -> true;
is_letter_lower("r") -> true;
is_letter_lower("s") -> true;
is_letter_lower("t") -> true;
is_letter_lower("u") -> true;
is_letter_lower("v") -> true;
is_letter_lower("x") -> true;
is_letter_lower("z") -> true;
is_letter_lower("a") -> true;
is_letter_lower("b") -> true;
is_letter_lower(_) -> false.


-spec is_number(string()) -> boolean().
is_number("") -> false;
is_number(V) -> [Char || Char <- V, Char < $0 orelse Char > $9] == [].


-spec is_cpf_valid(list() | binary()) -> boolean().
is_cpf_valid(S) when is_binary(S) ->
	is_cpf_valid(binary_to_list(S));
is_cpf_valid(S) ->
	case ems_util:is_number(S) andalso string:len(S) =:= 11 of
		true -> 
			C = [  X || X <- S, X > 47 andalso X < 58 ],
			D = ( lists:sum( lists:zipwith(fun(X,Y) -> (X-48)*Y end, C, [1,2,3,4,5,6,7,8,9,0,0]) ) rem 11 ) rem 10,
			D =:= lists:nth(10, C) - 48 andalso ( (lists:sum(lists:zipwith(fun(X,Y) -> (X-48)*Y end, C, [0,1,2,3,4,5,6,7,8,0,0]) ) + D * 9 ) rem 11) rem 10 =:= lists:nth(11, C) - 48;
		false -> false
	end.

-spec is_cnpj_valid(list() | binary()) -> boolean().		
is_cnpj_valid(S) when is_binary(S) -> 
	is_cnpj_valid(binary_to_list(S));
is_cnpj_valid(S) -> string:len(S) =:= 13.


load_erlang_module(Filename) ->
	ModuleName = filename:rootname(filename:basename(Filename)),
	ModuleNameAtom = list_to_atom(ModuleName),
	FilenameMod = filename:rootname(Filename) ++ ".erl",
	case filelib:file_size(FilenameMod) > 0 of
		true ->
			case code:ensure_loaded(ModuleNameAtom) of
				{module, _} -> {ok, ModuleNameAtom};
				_Error -> 
					FilenamePath = filename:dirname(Filename), 
					code:add_path(FilenamePath), 
					case compile:file(FilenameMod, [{outdir, FilenamePath ++ "/"}]) of
						error -> 
							io:format("[ ERROR ]\n"),
							{error, einvalid_module_sintax};
						{error, Errors, _Warnings} -> 
							io:format("[ ERROR ]\n"),
							io:format_error("~p\n", [Errors]),
							{error, einvalid_module_sintax};
						_ -> 
							io:format("[ OK ]\n"),
							{ok, ModuleNameAtom}
					end
			end;
		false -> {error, enoent}
	end.


replacenth(Index,Value,List) ->
 replacenth(Index-1,Value,List,[],0).

replacenth(ReplaceIndex,Value,[_|List],Acc,ReplaceIndex) ->
 lists:reverse(Acc)++[Value|List];
replacenth(ReplaceIndex,Value,[V|List],Acc,Index) ->
 replacenth(ReplaceIndex,Value,List,[V|Acc],Index+1).


-spec ip_list() -> {ok, list(tuple())} | {error, atom()}.
ip_list()->
	 case inet:getifaddrs() of
		{ok, List} ->
			List2 = [ hd_or_empty([ P || {ParamName, ParamValue} = P <- IfParams, ParamName == addr, tuple_size(ParamValue) == 4 ]) 
							|| {_IfName, IfParams} <- List ],
			List3 = [ element(2, X) || X <- List2, is_tuple(X) ],
			List4 = [ X || X <- List3, tuple_size(X) == 4 ],
			{ok, List4};
		Error -> Error
	end.


-spec ip_list(list(string())) -> {ok, list(tuple())} | {error, atom()}.
ip_list(TcpListenPrefixInterfaceNames)->
	 case inet:getifaddrs() of
		{ok, List} ->
			List2 = [ hd_or_empty([ P || {ParamName, ParamValue} = P <- IfParams, ParamName == addr, tuple_size(ParamValue) == 4 ]) 
							|| {IfName, IfParams} <- List, lists:any(fun(Prefix) -> lists:prefix(Prefix, IfName) end, TcpListenPrefixInterfaceNames) ],
			List3 = [ element(2, X) || X <- List2, is_tuple(X) ],
			List4 = [ X || X <- List3, tuple_size(X) == 4 ],
			{ok, List4};
		Error -> Error
	end.
	 

-spec parse_bool(binary() | string() | boolean() | integer()) -> boolean().
parse_bool(<<"true">>) -> true;
parse_bool(<<"1">>) -> true;
parse_bool("true") -> true;
parse_bool("1") -> true;
parse_bool(true) -> true;
parse_bool(1) -> true;
parse_bool(_) -> false.


-spec parse_service_service(binary() | string()) -> {string(), string(), string()}.
parse_service_service(Service) when is_binary(Service) ->
	parse_service_service(binary_to_list(Service));
parse_service_service(Service) ->
	try
		[ModuleName, FunctionName] = string:tokens(Service, ":"),
		ModuleName2 = ModuleName,
		FunctionName2 = FunctionName,
		ModuleNameCanonical = lists:last(string:tokens(ModuleName2, ".")),
		{ModuleName2, ModuleNameCanonical, FunctionName2}
	catch
		_Exception:_Reason ->  erlang:error(einvalid_service_service)
	end.

	 
%% @doc Translates the code into a more useful description
-spec posix_error_description(atom()) -> string().
posix_error_description(e2big) -> "e2big - argument list too long";
posix_error_description(eacces) -> "eacces - permission denied";
posix_error_description(eaddrinuse) -> "eaddrinuse - address already in use";
posix_error_description(eaddrnotavail) -> "eaddrnotavail - cannot assign requested address";
posix_error_description(eadv) -> "eadv - advertise error";
posix_error_description(eafnosupport) -> "eafnosupport - address family not supported by protocol family";
posix_error_description(eagain) -> "eagain - resource temporarily unavailable";
posix_error_description(ealign) -> "ealign - EALIGN";
posix_error_description(ealready) -> "ealready - operation already in progress";
posix_error_description(ebade) -> "ebade - bad exchange descriptor";
posix_error_description(ebadf) -> "ebadf - bad file number";
posix_error_description(ebadfd) -> "ebadfd - file descriptor in bad state";
posix_error_description(ebadmsg) -> "ebadmsg - not a data message";
posix_error_description(ebadr) -> "ebadr - bad request descriptor";
posix_error_description(ebadrpc) -> "ebadrpc - RPC structure is bad";
posix_error_description(ebadrqc) -> "ebadrqc - bad request code";
posix_error_description(ebadslt) -> "ebadslt - invalid slot";
posix_error_description(ebfont) -> "ebfont - bad font file format";
posix_error_description(ebusy) -> "ebusy - file busy";
posix_error_description(echild) -> "echild - no children";
posix_error_description(echrng) -> "echrng - channel number out of range";
posix_error_description(ecomm) -> "ecomm - communication error on send";
posix_error_description(econnaborted) -> "econnaborted - software caused connection abort";
posix_error_description(econnrefused) -> "econnrefused - connection refused";
posix_error_description(econnreset) -> "econnreset - connection reset by peer";
posix_error_description(edeadlk) -> "edeadlk - resource deadlock avoided";
posix_error_description(edeadlock) -> "edeadlock - resource deadlock avoided";
posix_error_description(edestaddrreq) -> "edestaddrreq - destination address required";
posix_error_description(edirty) -> "edirty - mounting a dirty fs w/o force";
posix_error_description(edom) -> "edom - math argument out of range";
posix_error_description(edotdot) -> "edotdot - cross mount point";
posix_error_description(edquot) -> "edquot - disk quota exceeded";
posix_error_description(eduppkg) -> "eduppkg - duplicate package name";
posix_error_description(eexist) -> "eexist - file already exists";
posix_error_description(efault) -> "efault - bad address in system call argument";
posix_error_description(efbig) -> "efbig - file too large";
posix_error_description(ehostdown) -> "ehostdown - host is down";
posix_error_description(ehostunreach) -> "ehostunreach - host is unreachable";
posix_error_description(eidrm) -> "eidrm - identifier removed";
posix_error_description(einit) -> "einit - initialization error";
posix_error_description(einprogress) -> "einprogress - operation now in progress";
posix_error_description(eintr) -> "eintr - interrupted system call";
posix_error_description(einval) -> "einval - invalid argument";
posix_error_description(eio) -> "eio - I/O error";
posix_error_description(eisconn) -> "eisconn - socket is already connected";
posix_error_description(eisdir) -> "eisdir - illegal operation on a directory";
posix_error_description(eisnam) -> "eisnam - is a named file";
posix_error_description(el2hlt) -> "el2hlt - level 2 halted";
posix_error_description(el2nsync) -> "el2nsync - level 2 not synchronized";
posix_error_description(el3hlt) -> "el3hlt - level 3 halted";
posix_error_description(el3rst) -> "el3rst - level 3 reset";
posix_error_description(elbin) -> "elbin - ELBIN";
posix_error_description(elibacc) -> "elibacc - cannot access a needed shared library";
posix_error_description(elibbad) -> "elibbad - accessing a corrupted shared library";
posix_error_description(elibexec) -> "elibexec - cannot exec a shared library directly";
posix_error_description(elibmax) -> "elibmax - attempting to link in more shared libraries than system limit";
posix_error_description(elibscn) -> "elibscn - .lib section in a.out corrupted";
posix_error_description(elnrng) -> "elnrng - link number out of range";
posix_error_description(eloop) -> "eloop - too many levels of symbolic links";
posix_error_description(emfile) -> "emfile - too many open files";
posix_error_description(emlink) -> "emlink - too many links";
posix_error_description(emsgsize) -> "emsgsize - message too long";
posix_error_description(emultihop) -> "emultihop - multihop attempted";
posix_error_description(enametoolong) -> "enametoolong - file name too long";
posix_error_description(enavail) -> "enavail - not available";
posix_error_description(enet) -> "enet - ENET";
posix_error_description(enetdown) -> "enetdown - network is down";
posix_error_description(enetreset) -> "enetreset - network dropped connection on reset";
posix_error_description(enetunreach) -> "enetunreach - network is unreachable";
posix_error_description(enfile) -> "enfile - file table overflow";
posix_error_description(enoano) -> "enoano - anode table overflow";
posix_error_description(enobufs) -> "enobufs - no buffer space available";
posix_error_description(enocsi) -> "enocsi - no CSI structure available";
posix_error_description(enodata) -> "enodata - no data available";
posix_error_description(enodev) -> "enodev - no such device";
posix_error_description(enoent) -> "enoent - no such file or directory";
posix_error_description(enoexec) -> "enoexec - exec format error";
posix_error_description(enolck) -> "enolck - no locks available";
posix_error_description(enolink) -> "enolink - link has be severed";
posix_error_description(enomem) -> "enomem - not enough memory";
posix_error_description(enomsg) -> "enomsg - no message of desired type";
posix_error_description(enonet) -> "enonet - machine is not on the network";
posix_error_description(enopkg) -> "enopkg - package not installed";
posix_error_description(enoprotoopt) -> "enoprotoopt - bad protocol option";
posix_error_description(enospc) -> "enospc - no space left on device";
posix_error_description(enosr) -> "enosr - out of stream resources or not a stream device";
posix_error_description(enosym) -> "enosym - unresolved symbol name";
posix_error_description(enosys) -> "enosys - function not implemented";
posix_error_description(enotblk) -> "enotblk - block device required";
posix_error_description(enotconn) -> "enotconn - socket is not connected";
posix_error_description(enotdir) -> "enotdir - not a directory";
posix_error_description(enotempty) -> "enotempty - directory not empty";
posix_error_description(enotnam) -> "enotnam - not a named file";
posix_error_description(Code) -> atom_to_list(Code).	 
	 

-spec allow_ip_address(tuple(), atom() | tuple()) -> boolean().
allow_ip_address(_, all) -> true;
allow_ip_address({127, 0, _,_}, _) -> true;
allow_ip_address(Ip, AllowedAddress) -> match_ip_address(AllowedAddress, Ip).


%% @doc Retorna o mime-type do arquivo
-spec mime_type(string()) -> string().
mime_type(".htm") -> <<"text/html">>;
mime_type(".html") -> <<"text/html">>;
mime_type(".json") -> <<"application/json">>;
mime_type(".xhtml") -> <<"application/xhtml+xml">>;
mime_type(".css") -> <<"text/css">>;
mime_type(".js") -> <<"application/x-javascript">>;
mime_type(".png") -> <<"image/png">>;
mime_type(".xml") -> <<"application/xml">>;
mime_type(".ico") -> <<"image/x-icon">>;
mime_type(".gif") -> <<"image/gif">>;
mime_type(".jpeg") -> <<"image/jpeg">>;
mime_type(".jpg") -> <<"image/jpeg">>;
mime_type(".pdf") -> <<"application/pdf">>;
mime_type(".bmp") -> <<"image/bmp">>;
mime_type(".txt") -> <<"text/plain">>;
mime_type(".ttf") -> <<"application/font-woff">>;
mime_type(".stl") -> <<"application/SLA">>;
mime_type(".stp") -> <<"application/STEP">>;
mime_type(".step") -> <<"application/STEP">>;
mime_type(".dwg") -> <<"application/acad">>;
mime_type(".ez") -> <<"application/andrew-inset">>;
mime_type(".ccad") -> <<"application/clariscad">>;
mime_type(".drw") -> <<"application/drafting">>;
mime_type(".tsp") -> <<"application/dsptype">>;
mime_type(".dxf") -> <<"application/dxf">>;
mime_type(".xls") -> <<"application/excel">>;
mime_type(".csv") -> <<"text/csv">>;
mime_type(".unv") -> <<"application/i-deas">>;
mime_type(".jar") -> <<"application/java-archive">>;
mime_type(".hqx") -> <<"application/mac-binhex40">>;
mime_type(".cpt") -> <<"application/mac-compactpro">>;
mime_type(".pot") -> <<"application/vnd.ms-powerpoint">>;
mime_type(".ppt") -> <<"application/vnd.ms-powerpoint">>;
mime_type(".dms") -> <<"application/octet-stream">>;
mime_type(".lha") -> <<"application/octet-stream">>;
mime_type(".lzh") -> <<"application/octet-stream">>;
mime_type(".oda") -> <<"application/oda">>;
mime_type(".ogg") -> <<"application/ogg">>;
mime_type(".ogm") -> <<"application/ogg">>;
mime_type(".pgp") -> <<"application/pgp">>;
mime_type(".ai") -> <<"application/postscript">>;
mime_type(".eps") -> <<"application/postscript">>;
mime_type(".ps") -> <<"application/postscript">>;
mime_type(".prt") -> <<"application/pro_eng">>;
mime_type(".rtf") -> <<"application/rtf">>;
mime_type(".smi") -> <<"application/smil">>;
mime_type(".smil") -> <<"application/smil">>;
mime_type(".sol") -> <<"application/solids">>;
mime_type(".vda") -> <<"application/vda">>;
mime_type(".xlm") -> <<"application/vnd.ms-excel">>;
mime_type(".cod") -> <<"application/vnd.rim.cod">>;
mime_type(".pgn") -> <<"application/x-chess-pgn">>;
mime_type(".cpio") -> <<"application/x-cpio">>;
mime_type(".csh") -> <<"application/x-csh">>;
mime_type(".deb") -> <<"application/x-debian-package">>;
mime_type(".dcr") -> <<"application/x-director">>;
mime_type(".dir") -> <<"application/x-director">>;
mime_type(".dxr") -> <<"application/x-director">>;
mime_type(".gz") -> <<"application/x-gzip">>;
mime_type(".hdf") -> <<"application/x-hdf">>;
mime_type(".ipx") -> <<"application/x-ipix">>;
mime_type(".ips") -> <<"application/x-ipscript">>;
mime_type(".skd") -> <<"application/x-koan">>;
mime_type(".skm") -> <<"application/x-koan">>;
mime_type(".skp") -> <<"application/x-koan">>;
mime_type(".skt") -> <<"application/x-koan">>;
mime_type(".latex") -> <<"application/x-latex">>;
mime_type(".lsp") -> <<"application/x-lisp">>;
mime_type(".scm") -> <<"application/x-lotusscreencam">>;
mime_type(".mif") -> <<"application/x-mif">>;
mime_type(".com") -> <<"application/x-msdos-program">>;
mime_type(".exe") -> <<"application/octet-stream">>;
mime_type(".cdf") -> <<"application/x-netcdf">>;
mime_type(".nc") -> <<"application/x-netcdf">>;
mime_type(".pl") -> <<"application/x-perl">>;
mime_type(".pm") -> <<"application/x-perl">>;
mime_type(".rar") -> <<"application/x-rar-compressed">>;
mime_type(".sh") -> <<"application/x-sh">>;
mime_type(".shar") -> <<"application/x-shar">>;
mime_type(".swf") -> <<"application/x-shockwave-flash">>;
mime_type(".sit") -> <<"application/x-stuffit">>;
mime_type(".sv4cpio") -> <<"application/x-sv4cpio">>;
mime_type(".sv4crc") -> <<"application/x-sv4crc">>;
mime_type(".tar.gz") -> <<"application/x-tar-gz">>;
mime_type(".tgz") -> <<"application/x-tar-gz">>;
mime_type(".tar") -> <<"application/x-tar">>;
mime_type(".tcl") -> <<"application/x-tcl">>;
mime_type(".texi") -> <<"application/x-texinfo">>;
mime_type(".texinfo") -> <<"application/x-texinfo">>;
mime_type(".man") -> <<"application/x-troff-man">>;
mime_type(".me") -> <<"application/x-troff-me">>;
mime_type(".ms") -> <<"application/x-troff-ms">>;
mime_type(".roff") -> <<"application/x-troff">>;
mime_type(".t") -> <<"application/x-troff">>;
mime_type(".tr") -> <<"application/x-troff">>;
mime_type(".ustar") -> <<"application/x-ustar">>;
mime_type(".src") -> <<"application/x-wais-source">>;
mime_type(".zip") -> <<"application/zip">>;
mime_type(".tsi") -> <<"audio/TSP-audio">>;
mime_type(".au") -> <<"audio/basic">>;
mime_type(".snd") -> <<"audio/basic">>;
mime_type(".kar") -> <<"audio/midi">>;
mime_type(".mid") -> <<"audio/midi">>;
mime_type(".midi") -> <<"audio/midi">>;
mime_type(".mp2") -> <<"audio/mpeg">>;
mime_type(".mp3") -> <<"audio/mpeg">>;
mime_type(".mpga") -> <<"audio/mpeg">>;
mime_type(".aif") -> <<"audio/x-aiff">>;
mime_type(".aifc") -> <<"audio/x-aiff">>;
mime_type(".aiff") -> <<"audio/x-aiff">>;
mime_type(".m3u") -> <<"audio/x-mpegurl">>;
mime_type(".wax") -> <<"audio/x-ms-wax">>;
mime_type(".wma") -> <<"audio/x-ms-wma">>;
mime_type(".rpm") -> <<"audio/x-pn-realaudio-plugin">>;
mime_type(".ram") -> <<"audio/x-pn-realaudio">>;
mime_type(".rm") -> <<"audio/x-pn-realaudio">>;
mime_type(".ra") -> <<"audio/x-realaudio">>;
mime_type(".wav") -> <<"audio/x-wav">>;
mime_type(".pdb") -> <<"chemical/x-pdb">>;
mime_type(".ras") -> <<"image/cmu-raster">>;
mime_type(".ief") -> <<"image/ief">>;
mime_type(".jpe") -> <<"image/jpeg">>;
mime_type(".jp2") -> <<"image/jp2">>;
mime_type(".tif") -> <<"image/tiff">>;
mime_type(".tiff") -> <<"image/tiff">>;
mime_type(".pnm") -> <<"image/x-portable-anymap">>;
mime_type(".pbm") -> <<"image/x-portable-bitmap">>;
mime_type(".pgm") -> <<"image/x-portable-graymap">>;
mime_type(".ppm") -> <<"image/x-portable-pixmap">>;
mime_type(".rgb") -> <<"image/x-rgb">>;
mime_type(".xbm") -> <<"image/x-xbitmap">>;
mime_type(".xwd") -> <<"image/x-xwindowdump">>;
mime_type(".iges") -> <<"model/iges">>;
mime_type(".igs") -> <<"model/iges">>;
mime_type(".mesh") -> <<"model/mesh">>;
mime_type(".msh") -> <<"model/mesh">>;
mime_type(".silo") -> <<"model/mesh">>;
mime_type(".vrml") -> <<"model/vrml">>;
mime_type(".wrl") -> <<"model/vrml">>;
mime_type(".asc") -> <<"text/plain">>;
mime_type(".c") -> <<"text/plain">>;
mime_type(".cc") -> <<"text/plain">>;
mime_type(".f90") -> <<"text/plain">>;
mime_type(".f") -> <<"text/plain">>;
mime_type(".hh") -> <<"text/plain">>;
mime_type(".m") -> <<"text/plain">>;
mime_type(".rtx") -> <<"text/richtext">>;
mime_type(".sgm") -> <<"text/sgml">>;
mime_type(".sgml") -> <<"text/sgml">>;
mime_type(".tsv") -> <<"text/tab-separated-values">>;
mime_type(".jad") -> <<"text/vnd.sun.j2me.app-descriptor">>;
mime_type(".etx") -> <<"text/x-setext">>;
mime_type(".dl") -> <<"video/dl">>;
mime_type(".fli") -> <<"video/fli">>;
mime_type(".flv") -> <<"video/flv">>;
mime_type(".gl") -> <<"video/gl">>;
mime_type(".mp4") -> <<"video/mp4">>;
mime_type(".mpe") -> <<"video/mpeg">>;
mime_type(".mpeg") -> <<"video/mpeg">>;
mime_type(".mpg") -> <<"video/mpeg">>;
mime_type(".mov") -> <<"video/quicktime">>;
mime_type(".qt") -> <<"video/quicktime">>;
mime_type(".viv") -> <<"video/vnd.vivo">>;
mime_type(".vivo") -> <<"video/vnd.vivo">>;
mime_type(".asf") -> <<"video/x-ms-asf">>;
mime_type(".asx") -> <<"video/x-ms-asx">>;
mime_type(".wmv") -> <<"video/x-ms-wmv">>;
mime_type(".wmx") -> <<"video/x-ms-wmx">>;
mime_type(".wvx") -> <<"video/x-ms-wvx">>;
mime_type(".avi") -> <<"video/x-msvideo">>;
mime_type(".movie") -> <<"video/x-sgi-movie">>;
mime_type(".mime") -> <<"www/mime">>;
mime_type(".ice") -> <<"x-conference/x-cooltalk">>;
mime_type(".vrm") -> <<"x-world/x-vrml">>;
mime_type(".spx") -> <<"audio/ogg">>;
mime_type(".bz2") -> <<"application/x-bzip2">>;
mime_type(".doc") -> <<"application/msword">>;
mime_type(".z") -> <<"application/x-compress">>;
mime_type(".m4a") -> <<"audio/mpeg">>;
mime_type(_) -> <<"application/octet-stream">>.

-spec is_valid_content_type(binary()) -> boolean().
is_valid_content_type(<<"text/html">>) -> true;
is_valid_content_type(<<"application/json">>) -> true;
is_valid_content_type(<<"application/json;charset=utf-8">>) -> true;
is_valid_content_type(<<"application/json; charset=utf-8">>) -> true;
is_valid_content_type(<<"application/xhtml+xml">>) -> true;
is_valid_content_type(<<"text/css">>) -> true;
is_valid_content_type(<<"application/x-javascript">>) -> true;
is_valid_content_type(<<"image/png">>) -> true;
is_valid_content_type(<<"application/xml">>) -> true;
is_valid_content_type(<<"image/x-icon">>) -> true;
is_valid_content_type(<<"image/gif">>) -> true;
is_valid_content_type(<<"image/jpeg">>) -> true;
is_valid_content_type(<<"application/pdf">>) -> true;
is_valid_content_type(<<"image/bmp">>) -> true;
is_valid_content_type(<<"text/plain">>) -> true;
is_valid_content_type(<<"application/font-woff">>) -> true;
is_valid_content_type(<<"application/acad">>) -> true;
is_valid_content_type(<<"application/andrew-inset">>) -> true;
is_valid_content_type(<<"application/clariscad">>) -> true;
is_valid_content_type(<<"application/drafting">>) -> true;
is_valid_content_type(<<"application/dsptype">>) -> true;
is_valid_content_type(<<"application/dxf">>) -> true;
is_valid_content_type(<<"application/excel">>) -> true;
is_valid_content_type(<<"text/csv">>) -> true;
is_valid_content_type(<<"application/i-deas">>) -> true;
is_valid_content_type(<<"application/java-archive">>) -> true;
is_valid_content_type(<<"application/mac-binhex40">>) -> true;
is_valid_content_type(<<"application/mac-compactpro">>) -> true;
is_valid_content_type(<<"application/vnd.ms-powerpoint">>) -> true;
is_valid_content_type(<<"application/octet-stream">>) -> true;
is_valid_content_type(<<"application/oda">>) -> true;
is_valid_content_type(<<"application/ogg">>) -> true;
is_valid_content_type(<<"application/pgp">>) -> true;
is_valid_content_type(<<"application/postscript">>) -> true;
is_valid_content_type(<<"application/pro_eng">>) -> true;
is_valid_content_type(<<"application/rtf">>) -> true;
is_valid_content_type(<<"application/smil">>) -> true;
is_valid_content_type(<<"application/solids">>) -> true;
is_valid_content_type(<<"application/vda">>) -> true;
is_valid_content_type(<<"application/vnd.ms-excel">>) -> true;
is_valid_content_type(<<"application/vnd.rim.cod">>) -> true;
is_valid_content_type(<<"application/x-chess-pgn">>) -> true;
is_valid_content_type(<<"application/x-cpio">>) -> true;
is_valid_content_type(<<"application/x-csh">>) -> true;
is_valid_content_type(<<"application/x-debian-package">>) -> true;
is_valid_content_type(<<"application/x-director">>) -> true;
is_valid_content_type(<<"application/x-gzip">>) -> true;
is_valid_content_type(<<"application/x-hdf">>) -> true;
is_valid_content_type(<<"application/x-ipix">>) -> true;
is_valid_content_type(<<"application/x-ipscript">>) -> true;
is_valid_content_type(<<"application/x-koan">>) -> true;
is_valid_content_type(<<"application/x-latex">>) -> true;
is_valid_content_type(<<"application/x-lisp">>) -> true;
is_valid_content_type(<<"application/x-lotusscreencam">>) -> true;
is_valid_content_type(<<"application/x-mif">>) -> true;
is_valid_content_type(<<"application/x-msdos-program">>) -> true;
is_valid_content_type(<<"application/x-netcdf">>) -> true;
is_valid_content_type(<<"application/x-perl">>) -> true;
is_valid_content_type(<<"application/x-rar-compressed">>) -> true;
is_valid_content_type(<<"application/x-sh">>) -> true;
is_valid_content_type(<<"application/x-shar">>) -> true;
is_valid_content_type(<<"application/x-shockwave-flash">>) -> true;
is_valid_content_type(<<"application/x-stuffit">>) -> true;
is_valid_content_type(<<"application/x-sv4cpio">>) -> true;
is_valid_content_type(<<"application/x-sv4crc">>) -> true;
is_valid_content_type(<<"application/x-tar-gz">>) -> true;
is_valid_content_type(<<"application/x-tar">>) -> true;
is_valid_content_type(<<"application/x-tcl">>) -> true;
is_valid_content_type(<<"application/x-texinfo">>) -> true;
is_valid_content_type(<<"application/x-troff-man">>) -> true;
is_valid_content_type(<<"application/x-troff-me">>) -> true;
is_valid_content_type(<<"application/x-troff-ms">>) -> true;
is_valid_content_type(<<"application/x-troff">>) -> true;
is_valid_content_type(<<"application/x-ustar">>) -> true;
is_valid_content_type(<<"application/x-wais-source">>) -> true;
is_valid_content_type(<<"application/zip">>) -> true;
is_valid_content_type(<<"audio/TSP-audio">>) -> true;
is_valid_content_type(<<"audio/basic">>) -> true;
is_valid_content_type(<<"audio/midi">>) -> true;
is_valid_content_type(<<"audio/mpeg">>) -> true;
is_valid_content_type(<<"audio/x-aiff">>) -> true;
is_valid_content_type(<<"audio/x-mpegurl">>) -> true;
is_valid_content_type(<<"audio/x-ms-wax">>) -> true;
is_valid_content_type(<<"audio/x-ms-wma">>) -> true;
is_valid_content_type(<<"audio/x-pn-realaudio-plugin">>) -> true;
is_valid_content_type(<<"audio/x-pn-realaudio">>) -> true;
is_valid_content_type(<<"audio/x-realaudio">>) -> true;
is_valid_content_type(<<"audio/x-wav">>) -> true;
is_valid_content_type(<<"chemical/x-pdb">>) -> true;
is_valid_content_type(<<"image/cmu-raster">>) -> true;
is_valid_content_type(<<"image/ief">>) -> true;
is_valid_content_type(<<"image/jp2">>) -> true;
is_valid_content_type(<<"image/tiff">>) -> true;
is_valid_content_type(<<"image/x-portable-anymap">>) -> true;
is_valid_content_type(<<"image/x-portable-bitmap">>) -> true;
is_valid_content_type(<<"image/x-portable-graymap">>) -> true;
is_valid_content_type(<<"image/x-portable-pixmap">>) -> true;
is_valid_content_type(<<"image/x-rgb">>) -> true;
is_valid_content_type(<<"image/x-xbitmap">>) -> true;
is_valid_content_type(<<"image/x-xwindowdump">>) -> true;
is_valid_content_type(<<"model/iges">>) -> true;
is_valid_content_type(<<"model/mesh">>) -> true;
is_valid_content_type(<<"model/vrml">>) -> true;
is_valid_content_type(<<"text/richtext">>) -> true;
is_valid_content_type(<<"text/sgml">>) -> true;
is_valid_content_type(<<"text/tab-separated-values">>) -> true;
is_valid_content_type(<<"text/vnd.sun.j2me.app-descriptor">>) -> true;
is_valid_content_type(<<"text/x-setext">>) -> true;
is_valid_content_type(<<"video/dl">>) -> true;
is_valid_content_type(<<"video/flv">>) -> true;
is_valid_content_type(<<"video/gl">>) -> true;
is_valid_content_type(<<"video/mp4">>) -> true;
is_valid_content_type(<<"video/mpeg">>) -> true;
is_valid_content_type(<<"video/quicktime">>) -> true;
is_valid_content_type(<<"video/vnd.vivo">>) -> true;
is_valid_content_type(<<"video/x-ms-asf">>) -> true;
is_valid_content_type(<<"video/x-ms-asx">>) -> true;
is_valid_content_type(<<"video/x-ms-wmx">>) -> true;
is_valid_content_type(<<"video/x-ms-wvx">>) -> true;
is_valid_content_type(<<"video/x-msvideo">>) -> true;
is_valid_content_type(<<"video/x-sgi-movie">>) -> true;
is_valid_content_type(<<"www/mime">>) -> true;
is_valid_content_type(<<"x-conference/x-cooltalk">>) -> true;
is_valid_content_type(<<"x-world/x-vrml">>) -> true;
is_valid_content_type(<<"audio/ogg">>) -> true;
is_valid_content_type(<<"application/x-bzip2">>) -> true;
is_valid_content_type(<<"application/msword">>) -> true;
is_valid_content_type(<<"application/x-compress">>) -> true;
is_valid_content_type(_) -> false.


-spec parse_content_type(binary()) -> binary().
parse_content_type(ContentType) ->
	case is_valid_content_type(ContentType) of
		true -> ContentType;
		false -> erlang:error(einvalid_content_type)
	end.


-spec invoque_service(binary(), binary(), binary()) -> {ok, request, #request{}} | {error, request, #request{}} | {error, atom()}.
invoque_service(Type, Url, QuerystringBin) -> 
	try
		case QuerystringBin of
			<<>> -> QuerystringMap = #{};
			_ -> 
				Querystring = case binary_to_list(QuerystringBin) of
									"?" ++ QuerystringValue -> QuerystringValue;
									QuerystringValue -> QuerystringValue
							  end,
				QuerystringMap = parse_querystring([Querystring])
		end,
		invoque_service(Type, Url, QuerystringBin, QuerystringMap, ?CONTENT_TYPE_JSON)
	catch
		_Exception:Reason -> 
			ems_logger:error("ems_util invoque_service ~p ~p with querystring ~p exception: ~p.", [Type, Url, QuerystringBin, Reason]),
			{error, einvoque_service}
	end.

invoque_service(Type, Url, QuerystringBin, QuerystringMap, ContentTypeIn) ->
	Url2 = remove_ult_backslash_url(binary_to_list(Url)),
	{Rowid, Params_url} = hashsym_and_params(Url2),
	RID = erlang:system_time(),
	Timestamp = calendar:local_time(),
	T1 = trunc(RID / 1.0e6), % optimized: same that get_milliseconds()
	Request = #request{
				rid = RID,
				rowid = Rowid,
				type = Type,
				uri = <<>>,
				url = Url2,
				version = <<>>,
				content_type_in = ContentTypeIn,
				content_length = 0,
				querystring = QuerystringBin,
				querystring_map = QuerystringMap,
				params_url = Params_url,
				accept = <<"*/*">>,
				user_agent = <<"ems-bus">>,
				user_agent_version = <<>>,
				accept_encoding = <<"*">>,
				cache_control = <<>>,
				ip = {127,0,0,1},
				ip_bin = <<"127.0.0.1">>,
				host = <<"localhost">>,
				timestamp = Timestamp,
				authorization = <<>>,
				worker_send = undefined,
				if_modified_since = <<>>,
				if_none_match = <<>>,
				protocol = http,
				protocol_bin = <<"http">>,
				port = 2301,
				result_cache = false,
				t1 = T1,
				referer = <<"ems-bus">>,
				payload = <<>>, 
				payload_map = #{},
				response_data = <<>>,
				node_exec = ems_util:node_binary()
			},	
	case ems_catalog_lookup:lookup(Request) of
		{Service = #service{content_type = ContentTypeService}, 
		 ParamsMap, 
		 QuerystringMap2} -> 
			 ReqHash = erlang:phash2([Url, QuerystringMap2, 0, ContentTypeIn]),
			 Request2 = Request#request{
						querystring_map = QuerystringMap2,
						content_type_out = 	case ContentTypeService of
												undefined -> ContentTypeIn;
												_ -> ContentTypeService
											end,
						params_url = ParamsMap,
						req_hash = ReqHash,
						service = Service},
			ems_dispatcher:dispatch_service_work(Request2, Service, false);
		 Error -> Error
	end.	

-spec url_mask(string() | binary()) -> binary().
url_mask(Url) -> iolist_to_binary([<<"/erl.ms/">>, base64:encode(Url)]). 

-spec url_mask_str(string() | binary()) -> string().
url_mask_str(Url) -> binary_to_list(iolist_to_binary([<<"/erl.ms/">>, base64:encode(Url)])). 


-spec encode_request_cowboy(tuple(), pid(), #encode_request_state{}) -> {ok, #request{}} | {error, atom()}.
encode_request_cowboy(CowboyReq, WorkerSend, #encode_request_state{http_header_default = HttpHeaderDefault,
																   http_header_options = HttpHeaderOptions, 
																   show_debug_response_headers = ShowDebugResponseHeaders,
																   current_node = CurrentNode}) ->
	try
		ems_logger:debug("CowboyReq ~p.", [CowboyReq]),
		Uri = iolist_to_binary(cowboy_req:uri(CowboyReq)),
		Url = binary_to_list(cowboy_req:path(CowboyReq)),
		case Url of
			"/dados/erl.ms/" ++ UrlEncoded -> 
				UrlMasked = true,
				Url1 = binary_to_list(base64:decode(UrlEncoded)),
				case Url1 of
					"/dados" ++ UrlRest -> UrlSemPrefix = UrlRest;
					_ -> UrlSemPrefix = Url1
				end,
				case string:find(UrlSemPrefix, "?") of
					nomatch -> 
						Url2 = remove_ult_backslash_url(UrlSemPrefix),
						QuerystringBin = <<>>,
						QuerystringMap0 = #{};
					"?" ++ Querystring -> 
						PosInterrogacao = string:chr(UrlSemPrefix, $?),
						Url2 = remove_ult_backslash_url(string:slice(UrlSemPrefix, 0, PosInterrogacao-1)),
						QuerystringBin = list_to_binary(Querystring),
						QuerystringMap0 = parse_querystring([Querystring])
				end;
			"/erl.ms/" ++ UrlEncoded -> 
				UrlMasked = true,
				Url1 = binary_to_list(base64:decode(UrlEncoded)),
				case Url1 of
					"/dados" ++ UrlRest -> UrlSemPrefix = UrlRest;
					_ -> UrlSemPrefix = Url1
				end,
				case string:find(UrlSemPrefix, "?") of
					nomatch -> 
						Url2 = remove_ult_backslash_url(UrlSemPrefix),
						QuerystringBin = <<>>,
						QuerystringMap0 = #{};
					"?" ++ Querystring -> 
						PosInterrogacao = string:chr(UrlSemPrefix, $?),
						Url2 = remove_ult_backslash_url(string:slice(UrlSemPrefix, 0, PosInterrogacao-1)),
						QuerystringBin = list_to_binary(Querystring),
						QuerystringMap0 = parse_querystring([Querystring])
				end;
			_ -> 
				UrlMasked = false,
				case Url of
					"/dados" ++ UrlRest -> UrlSemPrefix = UrlRest;
					_ -> UrlSemPrefix = Url
				end,
				QuerystringBin = cowboy_req:qs(CowboyReq),
				Url2 = remove_ult_backslash_url(UrlSemPrefix),
				case QuerystringBin of
					<<>> -> QuerystringMap0 = #{};
					_ -> QuerystringMap0 = parse_querystring([binary_to_list(QuerystringBin)])
				end
		end,
		RID = erlang:system_time(),
		Timestamp = calendar:local_time(),
		T1 = trunc(RID / 1.0e6), % optimized: same that get_milliseconds()
		Type = cowboy_req:method(CowboyReq),
		{Ip, _} = cowboy_req:peer(CowboyReq),
		IpBin = list_to_binary(inet_parse:ntoa(Ip)),
		case cowboy_req:header(<<"host">>, CowboyReq) of
			undefined -> Host = cowboy_req:host(CowboyReq);
			HostValue -> Host = HostValue
		end,
		Version = cowboy_req:version(CowboyReq),
		case cowboy_req:header(<<"content-type">>, CowboyReq) of
			undefined -> ContentTypeIn = <<>>;
			ContentTypeInValue -> ContentTypeIn = ContentTypeInValue
		end,
		ProtocolBin = cowboy_req:scheme(CowboyReq),
		Protocol = parse_protocol(ProtocolBin),
		Port = cowboy_req:port(CowboyReq),
		case cowboy_req:header(<<"accept">>, CowboyReq) of
			undefined -> Accept = <<"*/*">>;
			AcceptValue -> Accept = AcceptValue
		end,
		case cowboy_req:header(<<"accept-encoding">>, CowboyReq) of
			undefined -> Accept_Encoding = <<"*">>;
			AcceptEncodingValue -> Accept_Encoding = AcceptEncodingValue
		end,
		case cowboy_req:header(<<"user-agent">>, CowboyReq) of
			undefined -> UserAgentBrowser = <<>>;
			UserAgentBrowserValue -> UserAgentBrowser = UserAgentBrowserValue
		end,
		{UserAgent, UserAgentVersion} = parse_user_agent(UserAgentBrowser),
		case cowboy_req:header(<<"cache-control">>, CowboyReq) of
			undefined -> Cache_Control = <<>>;
			CacheControlValue -> Cache_Control = CacheControlValue
		end,
		case cowboy_req:header(<<"authorization">>, CowboyReq) of
			undefined -> Authorization = <<>>;
			AuthorizationValue -> Authorization = AuthorizationValue
		end,
		case cowboy_req:header(<<"if-modified-since">>, CowboyReq) of
			undefined -> IfModifiedSince = <<>>;
			IfModifiedSinceValue -> IfModifiedSince = IfModifiedSinceValue
		end,
		case cowboy_req:header(<<"if-none-match">>, CowboyReq) of
			undefined -> IfNoneMatch = <<>>;
			IfNoneMatchValue -> IfNoneMatch = IfNoneMatchValue
		end,
		case cowboy_req:header(<<"referer">>, CowboyReq) of
			undefined -> Referer = <<>>;
			RefererValue -> Referer = RefererValue
		end,
		case cowboy_req:header(<<"x-forwarded-for">>, CowboyReq) of
			undefined -> ForwardedFor = <<>>;
			ForwardedForValue -> ForwardedFor = ForwardedForValue
		end,
		{Rowid, Params_url} = hashsym_and_params(Url2),
		TypeLookup = case Type of
					<<"OPTIONS">> -> 
						ems_db:inc_counter(ems_dispatcher_options),
						<<"GET">>;
					<<"HEAD">> -> 
						ems_db:inc_counter(ems_dispatcher_head),
						<<"GET">>;
					<<"GET">> -> 
						ems_db:inc_counter(ems_dispatcher_get),
						<<"GET">>;
					<<"POST">> -> 
						ems_db:inc_counter(ems_dispatcher_post),
						<<"POST">>;
					<<"PUT">> -> 
						ems_db:inc_counter(ems_dispatcher_put),
						<<"PUT">>;
					<<"DELETE">> -> 
						ems_db:inc_counter(ems_dispatcher_delete),
						<<"DELETE">>;
					_ ->
						ems_db:inc_counter(ehttp_verb_not_supported),
						erlang:error(ehttp_verb_not_supported)
			   end,
		ems_logger:info("Request \033[01;34m~s\033[0m received \033[0;32muri\033[0m: \033[01;34m~s\033[0m \033[0;32murl\033[0m: \033[01;34m~s\033[0m \033[0;32mreferer\033[0m: \033[01;34m~s\033[0m \033[0;32mpeer\033[0m: \033[01;34m~s\033[0m \033[0;32muser-agent\033[0m: \033[01;34m~s\033[0m.", [binary_to_list(TypeLookup), binary_to_list(Uri), Url2, binary_to_list(Referer), binary_to_list(Host), binary_to_list(UserAgentBrowser)]),
	
		Request = #request{
			rid = RID,
			rowid = Rowid,
			type = TypeLookup,
			uri = Uri,
			url = Url2,
			url_masked = UrlMasked,
			version = Version,
			content_type_in = ContentTypeIn,
			content_type_out = ContentTypeIn,  %% Igual ao content_type_in pois não se sabe o contrato ainda
			content_length = 0,
			querystring = QuerystringBin,
			querystring_map = QuerystringMap0,
			params_url = Params_url,
			accept = Accept,
			user_agent = UserAgent,
			user_agent_version = UserAgentVersion,
			accept_encoding = Accept_Encoding,
			cache_control = Cache_Control,
			ip = Ip,
			ip_bin = IpBin,
			host = Host,
			timestamp = Timestamp,
			authorization = Authorization,
			worker_send = WorkerSend,
			if_modified_since = IfModifiedSince,
			if_none_match = IfNoneMatch,
			protocol = Protocol,
			protocol_bin = ProtocolBin,
			port = Port,
			result_cache = false,
			t1 = T1,
			referer = Referer,
			payload = <<>>, 
			payload_map = #{},
			response_data = <<>>,
			node_exec = CurrentNode,
			code = 200,
			reason = ok,
			reason_detail = undefined,
			operation = webservice,
			status_text = <<>>,
			forwarded_for = ForwardedFor
		},	
		case ems_catalog_lookup:lookup(Request) of
			{Service = #service{name = ServiceName,
								 service = ServiceService,	
								 url = ServiceUrl,
								 content_type = ContentTypeService,
								 owner = OwnerService,
								 group = GroupService,
								 version = ServiceVersion,
								 path = PathService,
								 cache_control = CacheControlService,
								 use_re = UseReService,
								 lang = LangService,
								 timeout = TimeoutService,
								 http_max_content_length = HttpMaxContentLengthService,
								 authorization = AuthorizationService,
								 expires = ExpiresService,
								 result_cache_shared = ResultCacheSharedService}, 
			 ParamsMap, 
			 QuerystringMap} -> 
				case cowboy_req:body_length(CowboyReq) of
					undefined -> ContentLength = 0; %% The value returned will be undefined if the length couldn't be figured out from the request headers. 
					ContentLengthValue -> ContentLength = ContentLengthValue
				end,
				case ContentLength > 0 of
					true ->
						case ContentLength > HttpMaxContentLengthService of
							true ->	
								ems_logger:error("ems_http_handler ehttp_max_content_length_error exception. HttpMaxContentLengthService of the request ~s ~s is ~p bytes.", [binary_to_list(Type), Url, HttpMaxContentLengthService]),
								erlang:error(ehttp_max_content_length_error);
							false -> ok
						end,
						ReadBodyOpts = #{length => HttpMaxContentLengthService + 8000, period => 190000, timeout => 180000},
						case ContentTypeIn of
							<<"application/json">> ->
								ems_db:inc_counter(http_content_type_in_application_json),
								ContentTypeIn2 = <<"application/json">>,
								{ok, Payload, CowboyReq2} = cowboy_req:read_body(CowboyReq, ReadBodyOpts),
								PayloadMap = decode_payload_as_json(Payload),
								QuerystringMap2 = QuerystringMap;
							<<"application/json; charset=utf-8">> ->
								ems_db:inc_counter(http_content_type_in_application_json),
								ContentTypeIn2 = <<"application/json">>,
								{ok, Payload, CowboyReq2} = cowboy_req:read_body(CowboyReq, ReadBodyOpts),
								PayloadMap = decode_payload_as_json(Payload),
								QuerystringMap2 = QuerystringMap;
							<<"application/json;charset=utf-8">> -> 
								ems_db:inc_counter(http_content_type_in_application_json),
								ContentTypeIn2 = <<"application/json">>,
								{ok, Payload, CowboyReq2} = cowboy_req:read_body(CowboyReq, ReadBodyOpts),
								PayloadMap = decode_payload_as_json(Payload),
								QuerystringMap2 = QuerystringMap;
							<<"application/x-www-form-urlencoded">> ->
								ems_db:inc_counter(http_content_type_in_form_urlencode),
								ContentTypeIn2 = <<"application/x-www-form-urlencoded">>,
								{ok, Payload, CowboyReq2} = cowboy_req:read_urlencoded_body(CowboyReq, ReadBodyOpts),
								PayloadMap = maps:from_list(Payload),
								QuerystringMap2 = maps:merge(QuerystringMap, PayloadMap);
							<<"application/x-www-form-urlencoded; charset=UTF-8">> ->
								ems_db:inc_counter(http_content_type_in_form_urlencode),
								ContentTypeIn2 = <<"application/x-www-form-urlencoded">>,
								{ok, Payload, CowboyReq2} = cowboy_req:read_urlencoded_body(CowboyReq, ReadBodyOpts),
								PayloadMap = maps:from_list(Payload),
								QuerystringMap2 = maps:merge(QuerystringMap, PayloadMap);
							<<"application/x-www-form-urlencoded;charset=UTF-8">> ->
								ems_db:inc_counter(http_content_type_in_form_urlencode),
								ContentTypeIn2 = <<"application/x-www-form-urlencoded">>,
								{ok, Payload, CowboyReq2} = cowboy_req:read_urlencoded_body(CowboyReq, ReadBodyOpts),
								PayloadMap = maps:from_list(Payload),
								QuerystringMap2 = maps:merge(QuerystringMap, PayloadMap);
							<<"application/xml">> ->
								ems_db:inc_counter(http_content_type_in_application_xml),
								ContentTypeIn2 = <<"application/xml">>,
								{ok, Payload, CowboyReq2} = cowboy_req:read_body(CowboyReq, ReadBodyOpts),
								PayloadMap = decode_payload_as_xml(Payload),
								QuerystringMap2 = QuerystringMap;
							<<"text/plain">> ->
								ems_db:inc_counter(http_content_type_in_text_plain),
								ContentTypeIn2 = ContentTypeIn,
								{ok, Payload, CowboyReq2} = cowboy_req:read_body(CowboyReq, ReadBodyOpts),
								PayloadMap = undefined,
								QuerystringMap2 = QuerystringMap;
							<<"text/csv">> ->
								ems_db:inc_counter(http_content_type_in_text_csv),
								ContentTypeIn2 = ContentTypeIn,
								{ok, Payload, CowboyReq2} = cowboy_req:read_body(CowboyReq, ReadBodyOpts),
								PayloadMap = undefined,
								QuerystringMap2 = QuerystringMap;
							<<"application/octet-stream">> ->
								ems_db:inc_counter(http_content_type_in_octet_stream),
								ContentTypeIn2 = ContentTypeIn,
								{ok, Payload, CowboyReq2} = cowboy_req:read_body(CowboyReq, ReadBodyOpts),
								PayloadMap = undefined,
								QuerystringMap2 = QuerystringMap;
							<<"application/gzip">> ->
								ems_db:inc_counter(http_content_type_in_application_gzip),
								ContentTypeIn2 = ContentTypeIn,
								{ok, Payload, CowboyReq2} = cowboy_req:read_body(CowboyReq, ReadBodyOpts),
								PayloadMap = undefined,
								QuerystringMap2 = QuerystringMap;
							<<"application/pdf">> ->
								ems_db:inc_counter(http_content_type_in_application_pdf),
								ContentTypeIn2 = ContentTypeIn,
								{ok, Payload, CowboyReq2} = cowboy_req:read_body(CowboyReq, ReadBodyOpts),
								PayloadMap = undefined,
								QuerystringMap2 = QuerystringMap;
							<<"application/msword">> ->
								ems_db:inc_counter(http_content_type_in_officedocument),
								ContentTypeIn2 = ContentTypeIn,
								{ok, Payload, CowboyReq2} = cowboy_req:read_body(CowboyReq, ReadBodyOpts),
								PayloadMap = undefined,
								QuerystringMap2 = QuerystringMap;
							<<"application/vnd.openxmlformats-officedocument.wordprocessingml.document">> ->
								ems_db:inc_counter(http_content_type_in_officedocument),
								ContentTypeIn2 = ContentTypeIn,
								{ok, Payload, CowboyReq2} = cowboy_req:read_body(CowboyReq, ReadBodyOpts),
								PayloadMap = undefined,
								QuerystringMap2 = QuerystringMap;
							<<"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet">> ->
								ems_db:inc_counter(http_content_type_in_officedocument),
								ContentTypeIn2 = ContentTypeIn,
								{ok, Payload, CowboyReq2} = cowboy_req:read_body(CowboyReq, ReadBodyOpts),
								PayloadMap = undefined,
								QuerystringMap2 = QuerystringMap;
							<<"image/png">> ->
								ems_db:inc_counter(http_content_type_in_image_png),
								ContentTypeIn2 = ContentTypeIn,
								{ok, Payload, CowboyReq2} = cowboy_req:read_body(CowboyReq, ReadBodyOpts),
								PayloadMap = undefined,
								QuerystringMap2 = QuerystringMap;
							<<"image/jpeg">> ->
								ems_db:inc_counter(http_content_type_in_image_jpeg),
								ContentTypeIn2 = ContentTypeIn,
								{ok, Payload, CowboyReq2} = cowboy_req:read_body(CowboyReq, ReadBodyOpts),
								PayloadMap = undefined,
								QuerystringMap2 = QuerystringMap;
							<<"multipart/form-data">> ->
								ems_db:inc_counter(http_content_type_in_formdata),
								ContentTypeIn2 = ContentTypeIn,
								{ok, Headers, CowboyReq1} = cowboy_req:read_part(CowboyReq),
								io:format("multipart/form-data headers is ~p\n", [Headers]),
								{ok, Payload, CowboyReq2} = cowboy_req:read_part_body(CowboyReq1),								
								{file, <<"inputfile">>, Filename, ContentType} = cow_multipart:form_data(Headers),

								io:format("Received file ~p of content-type ~p as follow:~n~p~n~n",
									[Filename, ContentType, Payload]),

								PayloadMap = undefined,
								QuerystringMap2 = QuerystringMap;
							_ -> 
								ems_db:inc_counter(http_content_type_in_other),
								ContentTypeIn2 = ContentTypeIn,
								{ok, Payload, CowboyReq2} = cowboy_req:read_body(CowboyReq, ReadBodyOpts),
								PayloadMap = undefined,
								QuerystringMap2 = QuerystringMap
						end;
					false ->
						ContentTypeIn2 = ContentTypeIn,						
						Payload = <<>>,
						PayloadMap = undefined,
						QuerystringMap2 = QuerystringMap,
						CowboyReq2 = CowboyReq
				end,
				case ResultCacheSharedService of
					true ->	ReqHash = erlang:phash2([Url, QuerystringMap2, ContentTypeIn2, Payload]);
					false -> ReqHash = erlang:phash2([Url, QuerystringMap2, ContentTypeIn2, AuthorizationService, IpBin, UserAgent, Payload])
				end,
				Request2 = Request#request{
					type = Type, % use original verb of request
					querystring_map = QuerystringMap2,
					content_type_in = ContentTypeIn2,
					content_type_out = 	case ContentTypeService of
											undefined -> ContentTypeIn2;
											_ -> ContentTypeService
										end,
					content_length = ContentLength,
					payload = Payload, 
					payload_map = PayloadMap,
					params_url = ParamsMap,
					req_hash = ReqHash,
					service = Service,
					response_header = case Type of
											<<"OPTIONS">> -> 
												ExpireDate = date_add_minute(Timestamp, 1440),
												Expires = cowboy_clock:rfc1123(ExpireDate),
												case ShowDebugResponseHeaders of
													false ->
														HttpHeaderOptions#{<<"expires">> => Expires,
																		   <<"cache-control">> => CacheControlService};
													true ->
														HttpHeaderOptions#{<<"X-ems-rowid">> => integer_to_binary(Rowid),
																		   <<"X-ems-hash">> => integer_to_binary(ReqHash),
																		   <<"X-ems-catalog">> => ServiceName,
																		   <<"X-ems-service">> => ServiceService,
																		   <<"X-ems-owner">> => OwnerService,
																		   <<"X-ems-group">> => GroupService,
																		   <<"X-ems-version">> => ServiceVersion,
																		   <<"X-ems-url">> => ServiceUrl,
																		   <<"X-ems-path">> => PathService,
																		   <<"X-ems-use-re">> => ems_util:boolean_to_binary(UseReService),
																		   <<"X-ems-cache-control">> => CacheControlService,
																		   <<"X-ems-timeout">> => integer_to_binary(TimeoutService),
																		   <<"X-ems-expires">> => integer_to_binary(ExpiresService),
																		   <<"X-ems-lang">> => LangService,
																		   <<"x-ems-authorization">> => atom_to_binary(AuthorizationService, utf8),
																		   <<"expires">> => Expires}
												end;
											_ -> 
												case ShowDebugResponseHeaders of
													false ->
														HttpHeaderDefault#{<<"cache_control">> => CacheControlService};
													true ->
														HttpHeaderDefault#{<<"X-ems-rowid">> => integer_to_binary(Rowid),
																		   <<"X-ems-hash">> => integer_to_binary(ReqHash),
																		   <<"X-ems-catalog">> => ServiceName,
																		   <<"X-ems-service">> => ServiceService,
																		   <<"X-ems-owner">> => OwnerService,
																		   <<"X-ems-group">> => GroupService,
																		   <<"X-ems-version">> => ServiceVersion,
																		   <<"X-ems-url">> => ServiceUrl,
																		   <<"X-ems-path">> => PathService,
																		   <<"X-ems-use-re">> => ems_util:boolean_to_binary(UseReService),
																		   <<"X-ems-cache-control">> => CacheControlService,
																		   <<"X-ems-timeout">> => integer_to_binary(TimeoutService),
																		   <<"X-ems-expires">> => integer_to_binary(ExpiresService),
																		   <<"X-ems-lang">> => LangService,
																		   <<"X-ems-authorization">> => atom_to_binary(AuthorizationService, utf8),
   																		   <<"cache-control">> => CacheControlService}
												end
									  end
				},	
				{ok, Request2, Service, CowboyReq2};
			_ -> 
				ReqHash = erlang:phash2([Url, QuerystringMap0, 0, ContentTypeIn]),
				Latency = ems_util:get_milliseconds() - T1,
				if 
					Type =:= <<"OPTIONS">> orelse Type =:= <<"HEAD">> ->
							StatusText = ems_util:format_rest_status(200, enoent_service_contract, undefined, undefined, Latency),
							case ShowDebugResponseHeaders of
								true ->
									Request2 = Request#request{req_hash = ReqHash,
																code = 200, 
																reason = enoent_service_contract,
																type = Type,  % use original verb of request
																response_header = HttpHeaderOptions#{<<"X-ems-status">> => StatusText},
																response_data = ?ENOENT_SERVICE_CONTRACT_JSON,
																latency = Latency,
																status_text = StatusText};
								false ->
									Request2 = Request#request{req_hash = ReqHash,
																code = 200, 
																reason = enoent_service_contract,
																type = Type,  % use original verb of request
																response_data = ?ENOENT_SERVICE_CONTRACT_JSON,
																latency = Latency,
																status_text = StatusText}
							end,
							{ok, request, Request2, CowboyReq};
					true ->
						ems_db:inc_counter(ems_dispatcher_lookup_enoent),								
						StatusText = ems_util:format_rest_status(404, enoent_service_contract, undefined, undefined, Latency),
						case ShowDebugResponseHeaders of
							true ->
								Request2 = Request#request{req_hash = ReqHash,
															code = 404, 
															reason = enoent_service_contract,
															type = Type,  % use original verb of request
															response_header = HttpHeaderDefault#{<<"X-ems-status">> => StatusText},
															response_data = ?ENOENT_SERVICE_CONTRACT_JSON,
															latency = Latency,
															status_text = StatusText};
							false ->
								Request2 = Request#request{req_hash = ReqHash,
															code = 404, 
															reason = enoent_service_contract,
															type = Type,  % use original verb of request
															response_header = HttpHeaderDefault,
															response_data = ?ENOENT_SERVICE_CONTRACT_JSON,
															latency = Latency,
															status_text = StatusText}
						end,
						{error, request, Request2, CowboyReq}
				end			
		end
	catch
		_Exception:ReasonException ->
			ems_logger:error("ems_util encode_request_cowboy failed. Reason: ~p.", [ReasonException]),
			{error, ReasonException}
	end.


parse_protocol(<<"http">>) -> http;
parse_protocol(<<"https">>) -> https;
parse_protocol(_) -> erlang:error(einvalid_protocol).


-spec parse_if_modified_since(binary() | undefined) -> calendar:datetime().
parse_if_modified_since(undefined) -> undefined;
parse_if_modified_since(IfModifiedSince) -> cow_date:parse_date(IfModifiedSince).

						
-spec parse_querystring(list()) -> list(tuple()).
parse_querystring(Q) ->
	Q1 = httpd:parse_query(Q),
	Q2 = [{iolist_to_binary(P), 
		   list_to_binary(case V of
										[34|_] -> remove_quoted_str(utf8_list_to_string(V));
										_  -> utf8_list_to_string(V)
						    end)}  || {P,V} <- Q1],
	maps:from_list(Q2).


-spec rid_to_string(integer()) -> list().
rid_to_string(RID) -> integer_to_list(RID).


method_to_string(Method) when is_atom(Method) -> atom_to_list(Method);
method_to_string(Method) -> Method.

decode_http_header(Headers, Params) ->
    case erlang:decode_packet(httph, Headers, []) of
        { ok, http_eoh, Rest } -> 
			{maps:from_list(Params), Rest};
        { ok, {http_header,_,P,_,V}, Rest } ->
            decode_http_header(Rest, [{P, V} | Params])
    end.

decode_http_request(RequestBin) ->
	case erlang:decode_packet(http_bin, RequestBin, []) of
		{ok, {http_error, _}, _} ->
			ems_logger:error("ems_util decode http error: ~p.", [RequestBin]),
			{error, http_error};
		{ok, Req, Rest} ->
			{http_request, Method, {abs_path, Uri}, {Http_Version_Major, Http_Version_Minor}} = Req,
			Http_Version = io_lib:format("HTTP/~p.~p", [Http_Version_Major, Http_Version_Minor]),
			case decode_http_header(Rest, []) of
				{error, ReasonDecodeHeader} -> {error, ReasonDecodeHeader};
				{Http_Params, Payload} -> {method_to_string(Method), 
										   binary_to_list(Uri), 
										   Http_Params, 
										   Http_Version,
										   Payload}
			end;
		{error, Reason} -> 
			ems_logger:error("ems_util decode http error: ~p.", [RequestBin]),
			{error, Reason}
	end.


%% @doc Decodifica o payload e transforma em um tipo Erlang
decode_payload_as_json(undefined) -> #{};
decode_payload_as_json(<<>>) -> #{};
decode_payload_as_json(PayloadBin) ->
	case json_decode_as_map(PayloadBin) of
		{ok, PayloadMap} -> PayloadMap;
		{error, _Reason} -> erlang:error(invalid_payload)
	end.

decode_payload_as_xml(undefined) -> #{};
decode_payload_as_xml(<<>>) -> #{};
decode_payload_as_xml(_) -> #{}.
	

-spec is_url_valido(binary() | string()) -> boolean().
is_url_valido(Url) when is_binary(Url) ->
	is_url_valido(binary_to_list(Url));
is_url_valido(Url) ->
	REPattern = ems_db:get_re_param(check_url_valid_re, "^((http:\/\/)|(\/))?([a-z_0-9\-]+\.)?[a-z_0-9\-.\/]+\.[a-z_0-9]{2,4}(\.[a-z0-9]{2,4})?(\/.*)?$"),
	case re:run(Url, REPattern) of
		nomatch -> false;
		_ -> true
	end.


-spec mask_ipaddress_to_tuple(binary()) -> tuple().
mask_ipaddress_to_tuple(<<IpAddress/binary>>) ->
	mask_ipaddress_to_tuple(binary_to_list(IpAddress));
mask_ipaddress_to_tuple(IpAddress) ->
	L = string:tokens(IpAddress, "."),
	L2 = lists:map(fun(X) -> 
								case X of
									"*" -> '_';
									_ -> list_to_integer(X)
								end
					end, L),
	list_to_tuple(L2).


%% @doc Retorna true se Ip2 combina com algum Ip da lista Ip1
-spec match_ip_address(list(), tuple()) -> boolean().
match_ip_address([Ip1|T], Ip2) ->
	case match_ip_address(Ip1, Ip2) of
		true -> true;
		false -> match_ip_address(T, Ip2)
	end;

%% @doc Retorna true se Ip2 combina com Ip1
match_ip_address([], _) -> false;
match_ip_address({O1, O2, O3, O4}, {X1, X2, X3, X4}) ->
   (O1 == '_' orelse O1 == X1) andalso
   (O2 == '_' orelse O2 == X2) andalso
   (O3 == '_' orelse O3 == X3) andalso
   (O4 == '_' orelse O4 == X4).
	
	
-spec parse_basic_authorization_header(Header :: binary()) -> {ok, string(), string()} | 
															  {error, access_denied, einvalid_basic_authorization_header | 
																					 ebasic_authorization_header_required | 
																					 eparse_basic_authorization_header_exception}.
parse_basic_authorization_header(<<Basic:5/binary, _:1/binary, Secret/binary>>) ->
	try
		case Basic =:= <<"Basic">> of
			true ->
				Secret2 = base64:decode_to_string(binary_to_list(Secret)),
				case string:tokens(Secret2, ":") of
					[Login, Password] -> {ok, Login, Password};
					[_Login] -> {error, access_denied, epassword_empty};
					_ -> {error, access_denied, einvalid_basic_authorization_header}
				end;
			false -> {error, access_denied, ebasic_authorization_header_required}
		end
	catch
		_:_ -> {error, access_denied, eparse_basic_authorization_header_exception}
	end;
parse_basic_authorization_header(_) -> {error, access_denied, eparse_basic_authorization_header_exception}.
	
	
-spec parse_bearer_authorization_header(Header :: binary()) -> {ok, binary()} | 
															   {error, access_denied, ebearer_authorization_header_required | 
																					  einvalid_bearer_authorization_header | 
																					  eparse_bearer_authorization_header_exception}.
parse_bearer_authorization_header(Header) ->
	try
		case Header of 
			<<Bearer:6/binary, _:1/binary, Secret/binary>> ->
				case Bearer =:= <<"Bearer">> of
					true ->	{ok, Secret};
					false -> {error, access_denied, ebearer_authorization_header_required}
				end;
			_ -> {error, access_denied, einvalid_bearer_authorization_header}
		end
	catch
		_:_ -> {error, access_denied, eparse_bearer_authorization_header_exception}
	end.
		

-spec parse_authorization_type(binary() | string() | oauth2 | basic | public | 0 | 1 | 2) -> atom().
parse_authorization_type(<<"Basic">>) -> basic;
parse_authorization_type(<<"basic">>) -> basic;
parse_authorization_type(<<"OAuth2">>) -> oauth2;
parse_authorization_type(<<"oauth2">>) -> oauth2;
parse_authorization_type(<<"Public">>) -> public;
parse_authorization_type(<<"public">>) -> public;
parse_authorization_type("Basic") -> basic;
parse_authorization_type("basic") -> basic;
parse_authorization_type("OAuth2") -> oauth2;
parse_authorization_type("oauth2") -> oauth2;
parse_authorization_type("Public") -> public;
parse_authorization_type("public") -> public;
parse_authorization_type(<<>>) -> public;
parse_authorization_type(oauth2) -> oauth2;
parse_authorization_type(basic) -> basic;
parse_authorization_type(public) -> public;
parse_authorization_type(0) -> public;
parse_authorization_type(1) -> basic;
parse_authorization_type(2) -> oauth2;
parse_authorization_type(_) -> erlang:error(einvalid_authorization_type).


-spec parse_result_cache(non_neg_integer()) -> non_neg_integer().
parse_result_cache(ResultCache) ->
	% Máximo permitido: 1 dia
	case is_integer(ResultCache) andalso ResultCache >= 0 andalso ResultCache =< 86400000 of
		true -> ResultCache;
		_ -> erlang:error(einvalid_result_cache)
	end.	


-spec parse_timeout(non_neg_integer(), non_neg_integer()) -> non_neg_integer().
parse_timeout(Timeout, MaxTimeout) ->
	case is_integer(Timeout) andalso Timeout > 0 andalso Timeout =< MaxTimeout of
		true -> Timeout;
		_ -> erlang:error(einvalid_timeout)
	end.	

-spec parse_type_service(binary() | string() | non_neg_integer()) -> binary(). 
parse_type_service(<<"GET">>) -> <<"GET">>;
parse_type_service(<<"POST">>) -> <<"POST">>;
parse_type_service(<<"PUT">>) -> <<"PUT">>;
parse_type_service(<<"DELETE">>) -> <<"DELETE">>;
parse_type_service(<<"OPTIONS">>) -> <<"OPTIONS">>;
parse_type_service(<<"KERNEL">>) -> <<"KERNEL">>;
parse_type_service("GET") -> <<"GET">>;
parse_type_service("POST") -> <<"POST">>;
parse_type_service("PUT") -> <<"PUT">>;
parse_type_service("DELETE") -> <<"DELETE">>;
parse_type_service("OPTIONS") -> <<"OPTIONS">>;
parse_type_service("KERNEL") -> <<"KERNEL">>;
parse_type_service(0) -> <<"KERNEL">>;
parse_type_service(1) -> <<"GET">>;
parse_type_service(2) -> <<"POST">>;
parse_type_service(3) -> <<"PUT">>;
parse_type_service(4) -> <<"DELETE">>;
parse_type_service(5) -> <<"OPTIONS">>;
parse_type_service(_) -> erlang:error(einvalid_type_service).


-spec parse_type_querystring(binary() | string() | non_neg_integer()) -> binary(). 
parse_type_querystring(<<"int">>) -> <<"int">>;
parse_type_querystring(<<"string">>) -> <<"string">>;
parse_type_querystring(0) -> <<"int">>;
parse_type_querystring(1) -> <<"string">>;
parse_type_querystring(_) -> erlang:error(einvalid_type_querystring).


-spec parse_url_service(binary() | list()) -> binary().
parse_url_service(<<"/">>) -> <<"/">>;
parse_url_service(Url) when is_binary(Url) ->
	parse_url_service(binary_to_list(Url));
parse_url_service(Url) ->
	LenUrl = length(Url),
	case LenUrl > 0 andalso LenUrl =< 360 andalso is_url_valido(Url) of
		true -> list_to_binary(Url);
		false -> 
			ems_logger:error("ems_util parse invalid url ~p.", [Url]),
			erlang:error(einvalid_url_service)
	end.

-spec parse_lang(binary() | string() | non_neg_integer()) -> binary().
parse_lang(<<"erlang">>) -> <<"erlang">>;
parse_lang("erlang") -> <<"erlang">>;
parse_lang(<<"java">>) -> <<"java">>;
parse_lang("java") -> <<"java">>;
parse_lang(0) -> <<"erlang">>;
parse_lang(1) -> <<"java">>;
parse_lang(_) -> <<"java">>.  %% default eh java

-spec parse_name_service(binary() | string()) -> binary().
parse_name_service(Name) when is_list(Name) ->
	parse_name_service(list_to_binary(Name));
parse_name_service(Name) ->
	REPattern = ems_db:get_re_param(check_name_service_valid_re, "^[/_a-zA-Z-.][.:/_a-zA-Z0-9-]{0,300}$"),
	case re:run(Name, REPattern) of
		nomatch -> erlang:error(einvalid_name_service);
		_ -> Name
	end.
	
parse_name_querystring(Name) when is_list(Name) ->
	parse_name_querystring(list_to_binary(Name));
parse_name_querystring(Name) ->
	REPattern = ems_db:get_re_param(check_name_querystring_valid_re, "^[_a-zA-Z][_a-zA-Z0-9]{0,29}$"),
	case re:run(Name, REPattern) of
		nomatch -> erlang:error(einvalid_name_querystring);
		_ -> Name
	end.
	
	
%% @doc Retorna uma mapa das querystrings e a quantidade de queries obrigatórias
-spec parse_querystring_def(list(), list()) -> {list(map()), non_neg_integer()}.	
parse_querystring_def(Querystring, RestDefaultQuerystring) -> parse_querystring_def(Querystring, [], 0, RestDefaultQuerystring).

	
%% @doc Retorna uma mapa das querystrings e a quantidade de queries obrigatórias
-spec parse_querystring_def(list(), list(), non_neg_integer(), list()) -> {list(map()), non_neg_integer()}.	
parse_querystring_def([], Querystring, QtdRequired, []) -> 	
	{Querystring, QtdRequired};
parse_querystring_def([], Querystring, QtdRequired, RestDefaultQuerystring) -> 	
	% Seleciona as queries default que não estão na lista Querystring
	RestDefaultQuerystring2 = lists:filtermap(fun(X) -> 
													Name = maps:get(<<"name">>, X),
													case lists:filtermap(fun(K) -> 
																				case maps:find(Name, K) of 
																					{ok, Name} -> true; 
																					_ -> false 
																				end
																		 end, Querystring) 
													of
															[] -> true;
															_ -> false
													end
											   end,  RestDefaultQuerystring),
 	Querystring2 = Querystring ++ RestDefaultQuerystring2, 
	{Querystring2, QtdRequired};
parse_querystring_def([H|T], Querystring, QtdRequired, RestDefaultQuerystring) -> 
	Name = parse_name_querystring(maps:get(<<"name">>, H)),
	Type = parse_type_querystring(maps:get(<<"type">>, H, <<"string">>)),
	Default = maps:get(<<"default">>, H, <<>>),
	Comment = maps:get(<<"comment">>, H, <<>>),
	Required = parse_bool(maps:get(<<"required">>, H, false)),
	case Required of
		true  -> QtdRequired2 = QtdRequired + 1;
		false -> QtdRequired2 = QtdRequired
	end,
	Q = #{<<"name">>     => Name,
		  <<"type">>     => Type,
		  <<"default">>  => Default,
		  <<"comment">>  => Comment,
		  <<"required">> => Required},
	% Não pode haver querystring duplicadas
	case lists:filtermap(fun(X) -> 
							case maps:find(<<"name">>, X) of 
								{ok, Name} -> true; 
								_ -> false 
							end
						 end,  Querystring) of
		[] ->
			% Localiza a query na lista de queryes default. Se existir faz o merge
			case lists:filtermap(fun(X) -> 
									case maps:find(<<"name">>, X) of 
										{ok, Name} -> true; 
										_ -> false 
									end
								 end,  RestDefaultQuerystring) of
				[] -> Q2 = Q;
				[DefaultQuery] -> Q2 = maps:merge(DefaultQuery, Q)
			end,
			parse_querystring_def(T, [Q2 | Querystring], QtdRequired2, RestDefaultQuerystring);
		_ ->  
			erlang:error(eduplicated_querystring_def)
	end.
	

	
-spec parse_tcp_listen_address(list(string()) | list(binary()) |  list(tuple()) | string() | binary() | undefined | null, list(string())) -> list(tuple()). 
parse_tcp_listen_address(undefined, _) -> [];
parse_tcp_listen_address(null, _) -> [];
parse_tcp_listen_address(<<>>, _) -> [];
parse_tcp_listen_address("", _) -> [];
parse_tcp_listen_address([{_,_,_,_}|_] = ListenAddress, _) -> ListenAddress;
parse_tcp_listen_address([H|_] = ListenAddress, TcpListenPrefixInterfaceNames) when is_binary(H) -> 
	parse_tcp_listen_address_t(ListenAddress, TcpListenPrefixInterfaceNames, []);
parse_tcp_listen_address([H|_] = ListenAddress, TcpListenPrefixInterfaceNames) when is_list(H) -> 
	parse_tcp_listen_address_t(ListenAddress, TcpListenPrefixInterfaceNames, []);
parse_tcp_listen_address(ListenAddress, TcpListenPrefixInterfaceNames) when is_binary(ListenAddress) ->
	parse_tcp_listen_address(binary_to_list(ListenAddress), TcpListenPrefixInterfaceNames);
parse_tcp_listen_address(ListenAddress, TcpListenPrefixInterfaceNames) ->
	ListenAddress2 = ems_util:str_trim(ListenAddress),
	case ListenAddress2 =/= "" of
		true ->	
			ListenAddress3 = [ems_util:str_trim(IP) || IP <- string:tokens(ListenAddress2, ",")],
			parse_tcp_listen_address_t(ListenAddress3, TcpListenPrefixInterfaceNames, []);
		false -> []
	end.

-spec parse_tcp_listen_address_t(list(string()) | list(binary()), list(tuple()), list(string())) -> list(tuple()). 
-ifdef(win32_plataform).
parse_tcp_listen_address_t([], _, Result) -> Result;
parse_tcp_listen_address_t([H|T], TcpListenPrefixInterfaceNames, Result) when is_binary(H) ->
	parse_tcp_listen_address_t([binary_to_list(H) | T], TcpListenPrefixInterfaceNames, Result);
parse_tcp_listen_address_t([H|T], TcpListenPrefixInterfaceNames, Result) ->
	IP = case H of
			 "*.*.*.*" -> "0.0.0.0";
			 Value -> Value
		  end,
	case inet:parse_address(IP) of
		{ok, {0, 0, 0, 0}} -> [{127,0,0,1}];
		{ok, L2} -> 
			case lists:member(L2, Result) of
				true -> parse_tcp_listen_address_t(T, TcpListenPrefixInterfaceNames, Result);
				false -> parse_tcp_listen_address_t(T, TcpListenPrefixInterfaceNames, [L2|Result])
			end;
		{error, einval} ->
			ems_logger:format_warn("ems_config parse invalid listen addresss ~p.", [H]),
			parse_tcp_listen_address_t(T, TcpListenPrefixInterfaceNames, Result)
	end.
-else.
parse_tcp_listen_address_t([], _, Result) -> Result;
parse_tcp_listen_address_t([H|T], TcpListenPrefixInterfaceNames, Result) when is_binary(H) ->
	parse_tcp_listen_address_t([binary_to_list(H) | T], TcpListenPrefixInterfaceNames, Result);
parse_tcp_listen_address_t([H|T], TcpListenPrefixInterfaceNames, Result) ->
	IP = case H of
			 "*.*.*.*" -> "0.0.0.0";
			 Value -> Value
		  end,
	case inet:parse_address(IP) of
		{ok, {0, 0, 0, 0}} ->
			case ip_list(TcpListenPrefixInterfaceNames) of
				{ok, IpList} -> IpList;
				_Error -> [{127,0,0,1}]
			end;
		{ok, L2} -> 
			case lists:member(L2, Result) of
				true -> parse_tcp_listen_address_t(T, TcpListenPrefixInterfaceNames, Result);
				false -> parse_tcp_listen_address_t(T, TcpListenPrefixInterfaceNames, [L2|Result])
			end;
		{error, einval} -> 
			ems_logger:format_warn("ems_config parse invalid listen addresss ~p.", [H]),
			parse_tcp_listen_address_t(T, TcpListenPrefixInterfaceNames, Result)
	end.
-endif.
	
-spec parse_allowed_address(all | undefined | null | binary() | string() | list()) -> list(tuple()).
parse_allowed_address(all) -> all;
parse_allowed_address(undefined) -> all;
parse_allowed_address(null) -> all;
parse_allowed_address(AllowedAddress) when is_binary(AllowedAddress) ->
	parse_allowed_address(binary_to_list(AllowedAddress));
parse_allowed_address(AllowedAddress) when is_list(AllowedAddress) ->
	AllowedAddress2 = ems_util:str_trim(AllowedAddress),
	case AllowedAddress2 =/= "" of
		true ->	
			AllowedAddress3 = [ems_util:str_trim(IP) || IP <- string:tokens(AllowedAddress2, ",")],
			parse_allowed_address_t(AllowedAddress3);
		false -> []
	end;
parse_allowed_address(AddrList) -> binlist_to_list(AddrList).

-spec parse_allowed_address_t(all | undefined | list()) -> all | undefined | list().
parse_allowed_address_t(all) -> all;
parse_allowed_address_t(undefined) -> undefined;
parse_allowed_address_t(null) -> undefined;
parse_allowed_address_t(AllowedAddress) -> 
	[mask_ipaddress_to_tuple(IP) || IP <- AllowedAddress].


-spec parse_tcp_port(undefined | binary() | string() | non_neg_integer()) -> non_neg_integer().
parse_tcp_port(undefined) -> undefined;
parse_tcp_port(<<Port/binary>>) -> 
	parse_tcp_port(binary_to_list(Port));		
parse_tcp_port(Port) when is_list(Port) -> 
	parse_tcp_port(list_to_integer(Port));
parse_tcp_port(Port) when is_integer(Port) -> 
	case is_range_valido(Port, ?TCP_PORT_MIN, ?TCP_PORT_MAX) of
		true -> Port;
		false -> erlang:error(einvalid_tcp_port)
	end.
	
	
-spec node_binary() -> binary().
node_binary() -> erlang:atom_to_binary(node(), utf8).   

uptime_str() ->
	{UpTime, _} = erlang:statistics(wall_clock),
    {D, {H, M, S}} = calendar:seconds_to_daystime(UpTime div 1000),
    lists:flatten(io_lib:format("~p days, ~p hours, ~p minutes and ~p seconds", [D,H,M,S])).
    

%% @doc Retorna um parâmetro do request
get_param_url(NomeParam, Default, Request) ->
	ParamsUrl = Request#request.params_url,
	NomeParam2 = iolist_to_binary(NomeParam),
	maps:get(NomeParam2, ParamsUrl, Default).


get_querystring(<<QueryName/binary>>, Service) ->	
	[Query] = [Q || Q <- maps:get(<<"querystring">>, Service, <<>>), Q#service.comment == QueryName],
	Query.


%% @doc Retorna uma querystring do request
get_querystring(QueryName, Default, #request{querystring_map = QuerystringMap}) ->
	Value = maps:get(QueryName, QuerystringMap, Default),
	case erlang:is_list(Value) of
		true -> list_to_binary(Value);
		false -> Value
	end.

get_querystring(QueryName, OrQueryName2, Default, #request{querystring_map = QuerystringMap}) ->
	Value = maps:get(QueryName, QuerystringMap, undefined),
	case Value =/= undefined andalso Value =/= <<>> of
		true ->	
			Value2 = maps:get(QueryName, QuerystringMap);
		false -> 
			Value2 = maps:get(OrQueryName2, QuerystringMap, Default)
	end,
	case erlang:is_list(Value2) of
		true -> list_to_binary(Value2);
		false -> Value2
	end.


load_from_file_req(Request = #request{url = Url,
									  if_modified_since = IfModifiedSinceReq, 
									  if_none_match = IfNoneMatchReq,
									  timestamp = Timestamp,
									  response_header = ResponseHeader,
									  service = #service{expires = ExpiresService,
														 path = Path,
														 filename = FilenameService,
														 show_debug_response_headers = ShowDebugResponseHeaders}}) ->
	case FilenameService == undefined  orelse FilenameService == <<>> of
		true -> Filename = Path ++ string:substr(Url, string:len(hd(string:tokens(Url, "/")))+2);
		false -> Filename = FilenameService
	end,
	case file:read_file_info(Filename, [{time, universal}]) of
		{ok,{file_info, FSize, _Type, _Access, _ATime, MTime, _CTime, _Mode,_,_,_,_,_,_}} -> 
			MimeType = mime_type(filename:extension(Filename)),
			ETag = integer_to_binary(erlang:phash2({FSize, MTime}, 16#ffffffff)),
			LastModified = cowboy_clock:rfc1123(MTime),
			ExpireDate = date_add_minute(Timestamp, ExpiresService + 180), 
			Expires = cowboy_clock:rfc1123(ExpireDate),
			ems_logger:info("ems_static_file_service reading file \033[01;34m~p\033[0m (Size: ~p bytes) from url \033[01;34m~p\033[0m.", [Filename, FSize, Url]),
			case ShowDebugResponseHeaders of
				true ->
					ResponseHeader2 = ResponseHeader#{
										<<"etag">> => ETag,
										<<"last-modified">> => LastModified,
										<<"expires">> => Expires,
										<<"X-ems-filename">> => list_to_binary(Filename)
									};
				false ->
					ResponseHeader2 = ResponseHeader#{
										<<"etag">> => ETag,
										<<"last-modified">> => LastModified,
										<<"expires">> => Expires
									}
			end,
			case ETag == IfNoneMatchReq orelse LastModified == IfModifiedSinceReq of
				true -> {ok, Request#request{code = 304, 
											 reason = enot_modified,
											 content_type_out = MimeType,
											 etag = ETag,
											 filename = Filename,
											 response_data = <<>>, 
											 response_header = ResponseHeader2}
						 };
				false ->
					case file:read_file(Filename) of
						{ok, FileData} -> 
							{ok, Request#request{code = 200, 
											      reason = ok,
												  content_type_out = MimeType,
											      etag = ETag,
											      filename = Filename,
											      response_data = FileData, 
											      response_header = ResponseHeader2}
							};
						{error, Reason} = Error -> 
							ems_logger:error("ems_static_file_service read file ~p from url ~p failed. Reason: ~p.", [Filename, Url, Reason]),
							{error, Request#request{code = case Reason of enoent -> 404; _ -> 400 end, 
												     reason = Reason,
												     content_type_out = ?CONTENT_TYPE_JSON,
												     response_data = ems_schema:to_json(Error)}
							}
					end
			end;
		{error, Reason} = Error -> 
			ems_logger:error("ems_static_file_service read file ~p from url ~p failed. Reason: ~p.", [Filename, Url, Reason]),
			{error, Request#request{code = case Reason of enoent -> 404; _ -> 400 end, 
									 reason = Reason,	
									 response_data = ems_schema:to_json(Error)}
			 }
	end.


save_from_file_req(Request = #request{url = _Url}) ->
		{ok, Request#request{code = 200, 
							 reason = ok,
							 content_type_out = ?CONTENT_TYPE_JSON,
							 response_data = ?OK_JSON}
		}.

-spec tuple_to_maps_with_keys(list(tuple()), list(tuple())) -> map().
tuple_to_maps_with_keys(Tuple, Keys) ->
	Fields = erlang:tuple_to_list(Tuple),
	Record = tuple_to_maps_with_keys(Fields, Keys, []),
	maps:from_list(Record).

tuple_to_maps_with_keys(_, [], Result) -> Result;
tuple_to_maps_with_keys([null|FldT], Keys, Result) ->
	tuple_to_maps_with_keys([undefined|FldT], Keys, Result);
tuple_to_maps_with_keys([FldH|FldT], Keys, Result) when is_list(FldH) ->
	tuple_to_maps_with_keys([list_to_binary(FldH)|FldT], Keys, Result);
tuple_to_maps_with_keys([FldH|FldT], [KeyH|KeyT], Result) ->
	tuple_to_maps_with_keys(FldT, KeyT, [{KeyH, FldH} | Result]).


	
%% *********** Functions for data validation ************

-spec is_range_valido(non_neg_integer(), integer(), integer()) -> boolean().
is_range_valido(Number, RangeIni, RangeFim) when Number >= RangeIni andalso Number =< RangeFim -> true;
is_range_valido(_Number, _RangeIni, _RangeFim) -> false.


-spec parse_range(non_neg_integer(), integer(), integer()) -> non_neg_integer.
parse_range(Number, RangeIni, RangeFim) when Number >= RangeIni andalso Number =< RangeFim -> Number;
parse_range(_, _, _) -> erlang:error(erange_not_allowed).

-spec parse_range(non_neg_integer(), integer(), integer(), atom()) -> non_neg_integer.
parse_range(Number, RangeIni, RangeFim, _) when Number >= RangeIni andalso Number =< RangeFim -> Number;
parse_range(_, _, _, Exception) -> erlang:error(Exception).


-spec parse_email(string() | binary()) -> binary() | undefined.
parse_email(Value) when is_binary(Value) ->
	parse_email(binary_to_list(Value));
parse_email(Value) ->
	case length(Value) > 8 of
		true ->
			Value2 = string:to_lower(Value),
			REPattern = ems_db:get_re_param(check_email_valid_re, "\\b[a-z0-9._%+-]+@[a-z0-9.-]+\\.[a-z]{2,4}\\b"),
			case re:run(Value2, REPattern) of
				nomatch -> erlang:error(einvalid_email);
				_ -> list_to_binary(Value2)
			end;
		false ->
			erlang:error(einvalid_email)
	end.
	

-spec is_email_valido(string() | binary()) -> boolean().
is_email_valido(Value) when is_binary(Value) -> 
	is_email_valido(binary_to_list(Value));
is_email_valido(Value) -> 
	REPattern = ems_db:get_re_param(check_email_valid_re, "\\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-z]{2,4}\\b"),
	case re:run(Value, REPattern) of
		nomatch -> false;
		_ -> true
	end.

%% @doc Retorna mensagem registro já existente
msg_registro_ja_existe(Pattern) ->
	case ems_db:existe(Pattern) of
		false -> [];
		_ -> <<"Registro já está cadastrado."/utf8>>
	end.

%% @doc Retorna mensagem registro já existente
msg_registro_ja_existe(Pattern, Message) ->
	case ems_db:existe(Pattern) of
		false -> [];
		_ -> Message
	end.
		
%% @doc Mensagens de campo obrigatório
msg_campo_obrigatorio(NomeCampo, []) -> 
	iolist_to_binary(io_lib:format(<<"Campo não preenchido: '~s'."/utf8>>, [NomeCampo]));
msg_campo_obrigatorio(NomeCampo, <<>>) -> 
	iolist_to_binary(io_lib:format(<<"Campo não preenchido: '~s'."/utf8>>, [NomeCampo]));
msg_campo_obrigatorio(_NomeCampo, _Value) -> [].

%% @doc Mensagem de e-mail inválido
msg_email_invalido(_NomeCampo, []) -> [];
msg_email_invalido(_NomeCampo, Value) -> 
	case is_email_valido(Value) of
		false -> iolist_to_binary(io_lib:format(<<"Email informado é inválido: '~s'."/utf8>>, [Value]));
		_ -> []
	end.

%% @doc Retorna somente mensagens não vazias
mensagens(L) -> lists:filter(fun(X) -> X /= [] end, L).

-spec parse_request_querystring(#service{}, #request{}) -> map().
parse_request_querystring(Service, Request) ->
	%% Querystrings do módulo ems_static_file_service e ems_options_service não são processados.
	QuerystringUser = Request#request.querystring_map,
	case Service#service.module of
		ems_static_file_service -> QuerystringUser;
		ems_options_service -> QuerystringUser;
		_ ->
			QuerystringServico = Service#service.querystring,
			case QuerystringUser =:= #{} of
				true -> 
					case QuerystringServico =:= [] of
						true -> QuerystringUser;
						false -> parse_request_querystring_defaults(QuerystringServico, QuerystringUser, [])
					end;
				false -> 
					case QuerystringServico =:= [] of
						true -> #{};
						false -> parse_request_querystring_defaults(QuerystringServico, QuerystringUser, [])
					end
			end
	end.

parse_request_querystring_defaults([], _QuerystringUser, QuerystringList) -> maps:from_list(QuerystringList);
parse_request_querystring_defaults([H|T], QuerystringUser, QuerystringList) ->
	%% Verifica se encontra a query na querystring do usuário
	NomeQuery = maps:get(<<"name">>, H),
	case maps:find(NomeQuery, QuerystringUser) of
		{ok, Value} -> 
			parse_request_querystring_defaults(T, QuerystringUser, [{NomeQuery, Value} | QuerystringList]);
		error ->
			%% se o usuário não informou a querystring, verifica se tem valor default na definição do serviço
			case maps:get(<<"default">>, H, enoent) of
				enoent -> [];
				Value -> parse_request_querystring_defaults(T, QuerystringUser, [{NomeQuery, Value} | QuerystringList])
			end
	end.

-spec compile_modulo_erlang(binary() | string() | undefined, binary() | string()) -> ok | {error, einvalidfilename} | {error, einvalid_dir}.
compile_modulo_erlang(undefined, _) -> ok;
compile_modulo_erlang(<<>>, _) -> ok;
compile_modulo_erlang(Path, ModuleNameCanonical) when is_binary(Path) ->
	compile_modulo_erlang(binary_to_list(Path), ModuleNameCanonical);
compile_modulo_erlang(Path, ModuleNameCanonical) when is_binary(ModuleNameCanonical) ->
	compile_modulo_erlang(Path, binary_to_list(ModuleNameCanonical));
compile_modulo_erlang(Path, ModuleNameCanonical) ->
	case filelib:is_dir(Path) of
		true ->
			Filename = filename:join(Path, ModuleNameCanonical) ++ ".erl",
			case filelib:is_regular(Filename) of
				true ->
					ems_logger:info("Compile file ~p ", [Filename]),
					code:add_path(Path), 
					case compile:file(Filename, [{outdir, Path ++ "/"}]) of
						error -> ems_logger:error("[ ERROR ]\n");
						{error, Errors, _Warnings} -> 
							ems_logger:error("[ ERROR ]\n"),
							ems_logger:error("~p\n", [Errors]);
						_ -> 
							ems_logger:error("[ OK ]\n"),
							ok
					end;
				_ -> {error, einvalid_filename}
			end;
		false -> {error, einvalid_dir}
	end.

-spec print_int_map(map()) -> binary().
print_int_map(Map) -> print_int_map(Map, maps:keys(Map), maps:values(Map), <<>>, []).

-spec print_int_map(map(), list(), list(), binary(), list()) -> binary().
print_int_map(_, [], _, _, Result) -> iolist_to_binary(lists:reverse(Result));
print_int_map(Map, [Key|TKey], [Value|TValue], Sep, Result) ->
	print_int_map(Map, TKey, TValue, <<", ">>, [[Sep, Key, <<"=">>, integer_to_binary(Value)] | Result]).
	

-spec print_str_map(map()) -> binary().
print_str_map(Map) -> print_str_map(Map, maps:keys(Map), maps:values(Map), <<>>, []).

-spec print_str_map(map(), list(), list(), binary(), list()) -> binary().
print_str_map(_, [], _, _, Result) -> iolist_to_binary(lists:reverse(Result));
print_str_map(Map, [Key|TKey], [Value|TValue], Sep, Result) ->
	print_str_map(Map, TKey, TValue, <<", ">>, [[Sep, Key, <<"=\"">>, Value, <<"\"">>] | Result]).


list_to_atomlist_with_trim([], Result) -> lists:reverse(Result);
list_to_atomlist_with_trim([H|T], Result) ->
	list_to_atomlist_with_trim(T, [list_to_atom(ems_util:str_trim(H))|Result]).

list_to_atomlist_with_trim([]) -> [];
list_to_atomlist_with_trim(<<>>) -> [];
list_to_atomlist_with_trim(undefined) -> [];
list_to_atomlist_with_trim(L) ->
	list_to_atomlist_with_trim(L, []).


binlist_to_atomlist_with_trim([], Result) -> lists:reverse(Result);
binlist_to_atomlist_with_trim([H|T], Result) ->
	binlist_to_atomlist_with_trim(T, [list_to_atom(ems_util:str_trim(binary_to_list(H)))|Result]).

binlist_to_atomlist_with_trim([]) -> [];
binlist_to_atomlist_with_trim(<<>>) -> [];
binlist_to_atomlist_with_trim(undefined) -> [];
binlist_to_atomlist_with_trim(L) ->
	binlist_to_atomlist_with_trim(L, []).
	

-spec binlist_to_atomlist(list(binary()) | binary()) -> list(atom()) | atom().
binlist_to_atomlist([])  -> [];
binlist_to_atomlist(undefined)  -> [];
binlist_to_atomlist(<<>>)  -> [];
binlist_to_atomlist(Value) when is_list(Value) ->
	binlist_to_atomlist_(Value, []);
binlist_to_atomlist(Value)  ->
	binary_to_atom(Value, utf8).

binlist_to_atomlist_([], Result) -> lists:reverse(Result);
binlist_to_atomlist_([H|T], Result) ->
	binlist_to_atomlist_(T, [binary_to_atom(H, utf8)|Result]).
	
	
atomlist_to_binlist([])  -> [];
atomlist_to_binlist(undefined)  -> [];
atomlist_to_binlist(<<>>)  -> [];
atomlist_to_binlist(Value) ->
	atomlist_to_binlist_(Value, []).

atomlist_to_binlist_([], Result) -> lists:reverse(Result);
atomlist_to_binlist_([H|T], Result) ->
	atomlist_to_binlist_(T, [atom_to_binary(H, utf8)|Result]).
	
atomlist_to_list([])  -> [];
atomlist_to_list(undefined)  -> [];
atomlist_to_list(<<>>)  -> [];
atomlist_to_list(Value) ->
	atomlist_to_list_(Value, []).

atomlist_to_list_([], Result) -> lists:reverse(Result);
atomlist_to_list_([H|T], Result) ->
	atomlist_to_list_(T, [atom_to_list(H)|Result]).
	

-spec json_field_strip_and_escape(string() | binary()) -> iolist().
json_field_strip_and_escape([]) ->	<<"null"/utf8>>;
json_field_strip_and_escape(<<>>) -> <<"null"/utf8>>;
json_field_strip_and_escape(undefined) -> <<"null"/utf8>>;
json_field_strip_and_escape(Value) when is_binary(Value) ->
	json_field_strip_and_escape(binary_to_list(Value));
json_field_strip_and_escape(Value) -> 
	case string:strip(Value) of
		[] -> <<"null"/utf8>>;
		ValueStrip -> 
			ValueEscaped = [case Ch of 
									34 -> "\\\""; 
									_ -> Ch 
							end || Ch <- ValueStrip],
			[<<"\""/utf8>>, ValueEscaped, <<"\""/utf8>>]
	end.

-spec parse_user_agent(binary() | string()) -> tuple().
parse_user_agent(<<>>) -> {browser_other, ""};
parse_user_agent(undefined) -> {browser_other, ""};
parse_user_agent(<<"undefined">>) -> {browser_other, ""};
parse_user_agent(UserAgent) when is_binary(UserAgent) ->
	parse_user_agent(binary_to_list(UserAgent));
parse_user_agent(UserAgent) ->
	case string:rstr(UserAgent, "Chrome/") of
		PosChrome when PosChrome > 0 ->
			BrowserName = browser_chrome,
			BrowserVersion = parse_user_agent_version(string:substr(UserAgent, PosChrome+7, 4));
		0 ->
			case string:rstr(UserAgent, "Firefox/") of
				PosFirefox when PosFirefox > 0 ->
					BrowserName = browser_firefox,
					BrowserVersion = parse_user_agent_version(string:substr(UserAgent, PosFirefox+8, 4));
				0 ->
					case string:rstr(UserAgent, "Trident/") of
						PosTrident when PosTrident > 0 ->
							BrowserName = browser_ie,
							BrowserVersion = parse_user_agent_version(string:substr(UserAgent, PosTrident+8, 4));
						0 ->
							case string:rstr(UserAgent, "Edge/") of
								PosEdge when PosEdge > 0 ->
									BrowserName = browser_edge,
									BrowserVersion = parse_user_agent_version(string:substr(UserAgent, PosEdge+5, 4));
								0 ->
									case string:rstr(UserAgent, "OPR/") of
										PosOpera when PosOpera > 0 ->
											BrowserName = browser_opera,
											BrowserVersion = parse_user_agent_version(string:substr(UserAgent, PosOpera+4, 4));
										0 ->
											case string:rstr(UserAgent, "insomnia/") of
												PosInsomnia when PosInsomnia > 0 ->
													BrowserName = browser_insomnia,
													BrowserVersion = parse_user_agent_version_subversion(string:substr(UserAgent, PosInsomnia+9, 5));
												0 ->
													case string:rstr(UserAgent, "Safari/") of
														PosSafari when PosSafari > 0 ->
															BrowserName = browser_safari,
															BrowserVersion = parse_user_agent_version(string:substr(UserAgent, PosSafari+7, 4));
														0 ->
															BrowserName = browser_other,
															BrowserVersion = ""
													end
											end
									end
							end
					end
			end
	end,
	{BrowserName, list_to_binary(BrowserVersion)}.

parse_user_agent_version(Version) -> parse_user_agent_version(Version, []).
parse_user_agent_version([], Result) -> lists:reverse(Result);
parse_user_agent_version([$.|_], Result) -> lists:reverse(Result);
parse_user_agent_version([H|T], Result) -> 
  parse_user_agent_version(T, [H|Result]).

parse_user_agent_version_subversion(Version) ->
	parse_user_agent_version_subversion(Version, false, []).
parse_user_agent_version_subversion([], _, Result) -> lists:reverse(Result);
parse_user_agent_version_subversion([$.|_], true, Result) -> lists:reverse(Result);
parse_user_agent_version_subversion([$.|T], false, Result) -> 
	parse_user_agent_version_subversion(T, true, [$.|Result]);
parse_user_agent_version_subversion([H|T], Stop, Result) -> 
  parse_user_agent_version_subversion(T, Stop, [H|Result]).
		
-spec user_agent_atom_to_binary(atom()) -> binary().
user_agent_atom_to_binary(browser_chrome) -> <<"Chrome">>;
user_agent_atom_to_binary(browser_firefox) -> <<"Firefox">>;
user_agent_atom_to_binary(browser_ie) -> <<"IE">>;
user_agent_atom_to_binary(browser_insomnia) -> <<"Insomnia">>;
user_agent_atom_to_binary(browser_opera) -> <<"Opera">>;
user_agent_atom_to_binary(browser_safari) -> <<"Safari">>;
user_agent_atom_to_binary(_) -> <<"Other">>.


-spec to_lower_and_remove_backslash(string() | binary()) -> binary().
to_lower_and_remove_backslash(undefined) -> <<>>;
to_lower_and_remove_backslash(<<>>) -> <<>>;
to_lower_and_remove_backslash(<<"/">>) -> <<"/">>;
to_lower_and_remove_backslash("/") -> <<"/">>;
to_lower_and_remove_backslash(Uri) when is_binary(Uri) ->
	to_lower_and_remove_backslash(binary_to_list(Uri));
to_lower_and_remove_backslash(Uri) ->	
	list_to_binary(string:to_lower(remove_ult_backslash_url(Uri))).
	
	
-spec check_type_email(binary(), binary()) -> 1 | 2.
check_type_email("", _) -> 2;
check_type_email(SufixoEmailInstitucional, Email) ->
	case lists:suffix(SufixoEmailInstitucional, binary_to_list(Email)) of
		true -> 1;
		false -> 2
	end.

-spec is_email_institucional(binary(), binary()) -> boolean().
is_email_institucional("", _) -> false;
is_email_institucional(SufixoEmailInstitucional, Email) ->
	case lists:suffix(SufixoEmailInstitucional, binary_to_list(Email)) of
		true -> true;
		false -> false
	end.

-spec get_client_request_by_id_and_secret(#request{}) -> {ok, #client{}} | {error, enoent, atom()}.
get_client_request_by_id_and_secret(Request = #request{authorization = Authorization,
													   user_agent = UserAgent,
													   ip_bin = Peer,
													   forwarded_for = ForwardedFor}) ->

    try
		case get_querystring(<<"client_id">>, <<>>, Request) of
			<<>> -> ClientId = 0;
			undefined -> ClientId = 0;
			ClientIdValue -> ClientId = binary_to_integer(ClientIdValue)
		end,
		case ClientId > 0 of
			true ->
				ClientSecret = ems_util:get_querystring(<<"client_secret">>, <<>>, Request),
				case ems_client:find_by_id_and_secret(ClientId, ClientSecret) of
					{ok, Client} -> {ok, Client#client{user_agent = UserAgent, peer = Peer, forwarded_for = ForwardedFor}};
					Error -> 
						io:format("emsutil:get_client_request_by_id_and_secret falhou ao localizar id %d", ClientId),
						Error
				end;
			false ->
				% O ClientId também pode ser passado via header Authorization
				case Authorization =/= undefined of
					true ->
						case parse_basic_authorization_header(Authorization) of
							{ok, ClientLogin, ClientSecret} ->
								ClientId2 = list_to_integer(ClientLogin),
								ClientSecret2 = list_to_binary(ClientSecret),
								case ClientId2 > 0 of
									true ->
										case ems_client:find_by_id_and_secret(ClientId2, ClientSecret2) of
											{ok, Client} -> {ok, Client#client{user_agent = UserAgent, peer = Peer, forwarded_for = ForwardedFor}};
											Error -> Error
										end;
									false -> {error, access_denied, einvalid_client_id}
								end;
							Error -> Error
						end;
					false -> {error, access_denied, eauthorization_header_required}
				end
		end
	catch
		_:ReasonException -> 
			ems_logger:error("ems_util get_client_request_by_id_and_secret exception. Request: ~p. Reason: ~p.", [Request, ReasonException]),
			{error, access_denied, eparse_get_client_request_by_id_and_secret_exception}
	end.


-spec get_client_request_by_id(#request{}) -> {ok, #client{}} | {error, enoent, atom()}.
get_client_request_by_id(Request = #request{authorization = Authorization,
											user_agent = UserAgent,
											ip_bin = Peer,
											forwarded_for = ForwardedFor}) ->
    try
		case get_querystring(<<"client_id">>, <<>>, Request) of
			<<>> -> ClientId = 0;
			undefined -> ClientId = 0;
			ClientIdValue -> ClientId = binary_to_integer(ClientIdValue)
		end,
		case get_querystring(<<"state">>, <<>>, Request) of
			<<>> -> State = <<>>;
			undefined -> State = <<>>;
			StateValue -> State = StateValue
		end,
		case ClientId > 0 of
			true ->
				case ems_client:find_by_id(ClientId) of
					{ok, Client} -> 
						{ok, Client#client{user_agent = UserAgent, peer = Peer, forwarded_for = ForwardedFor, state = State}};
					Error -> 
						ems_logger:error("ems_util get_client_request_by_id_and_secret failed on find_by_id. client_id: ~p. Reason: ~p.", [ClientId, Error]),
						{error, access_denied, enoent}
				end;
			false ->
				% O ClientId também pode ser passado via header Authorization
				case Authorization =/= undefined of
					true ->
						case parse_basic_authorization_header(Authorization) of
							{ok, ClientLogin, _} ->
								ClientId2 = list_to_integer(ClientLogin),
								case ClientId2 > 0 of 	
									true ->
										case ems_client:find_by_id(ClientId2) of
											{ok, Client} -> 
												{ok, Client#client{user_agent = UserAgent, peer = Peer, forwarded_for = ForwardedFor, state = State}};
											Error -> 
												ems_logger:error("ems_util get_client_request_by_id_and_secret failed on find_by_id. client_id: ~p. Reason: ~p.", [ClientId, Error]),
												{error, access_denied, enoent}
										end;
									false -> 
										{error, access_denied, einvalid_client_id}
								end;
							Error -> 
								ems_logger:error("ems_util get_client_request_by_id_and_secret on parse_basic_authorization_header failed. client_id: ~p. Reason: ~p.", [ClientId, Error]),
								Error
						end;
					false -> 
						{error, access_denied, eauthorization_header_required}
				end
		end
	catch
		_:ReasonException -> 
			ems_logger:error("ems_util get_client_request_by_id exception. Request: ~p. Reason: ~p.", [Request, ReasonException]),
			{error, access_denied, eparse_get_client_request_by_id_exception}
	end.


-spec get_user_request_by_login_and_password(#request{}) -> {ok, #user{}} | {error, 
																			 access_denied, 
																			 enoent, einvalid_password | einative_user | 
																			 einvalid_authorization_header | 
																			 eparse_authorization_header_exception}.
get_user_request_by_login_and_password(Request) ->
	get_user_request_by_login_and_password(Request, undefined).


-spec get_user_request_by_login_and_password(#request{}, #client{}) -> {ok, #user{}} | 
																			{error, 
																			 access_denied, 
																			 enoent, einvalid_password | einative_user | 
																			 einvalid_authorization_header | 
																			 eparse_authorization_header_exception}.
get_user_request_by_login_and_password(Request = #request{authorization = Authorization, 
														  service = #service{auth_allow_user_inative_credentials = AuthAllowUserInativeCredentials}},
									   Client) ->
    try
		Username = ems_util:get_querystring(<<"username">>, <<>>, Request),
		case Username =/= <<>> of
			true ->
				Password = ems_util:get_querystring(<<"password">>, <<>>, Request),
				case ems_user:find_by_login_and_password(Username, Password, Client) of
					{ok, User = #user{active = Active}} -> 
						case Active orelse AuthAllowUserInativeCredentials of
							true -> {ok, User};
							false -> {error, access_denied, einative_user}
						end;
					Error -> Error
				end;
			false ->
				% O user também pode ser passado via header Authorization
				case Authorization =/= undefined of
					true ->
						case parse_basic_authorization_header(Authorization) of
							{ok, Login, Password} ->
								case ems_user:find_by_login_and_password(Login, Password, Client) of
									{ok, User = #user{active = Active}} -> 
										case Active orelse AuthAllowUserInativeCredentials of
											true -> {ok, User};
											false -> {error, access_denied, einative_user}
										end;
									Error -> Error
								end;
							Error -> Error
						end;
					false -> {error, access_denied, eauthorization_header_required}
				end
		end
	catch
		_:_ -> {error, access_denied, eparse_get_user_request_by_login_and_password_exception}
	end.


-spec get_user_request_by_login(#request{}) -> {ok, #user{}} | {error, enoent | access_denied, atom()}.
get_user_request_by_login(Request = #request{authorization = Authorization}) ->
    try
		Username = ems_util:get_querystring(<<"username">>, <<>>, Request),
		case Username =/= <<>> of
			true ->
				case ems_user:find_by_login(Username) of
					{ok, User} -> {ok, User};
					Error -> Error
				end;
			false ->
				% O user também pode ser passado via header Authorization
				case Authorization =/= undefined of
					true ->
						case parse_basic_authorization_header(Authorization) of
							{ok, Login, _Password} ->
								case ems_user:find_by_login(Login) of
									{ok, User} -> {ok, User};
									Error -> Error
								end;
							Error -> Error
						end;
					false -> {error, access_denied, eauthorization_header_required}
				end
		end
	catch
		_:_ -> {error, access_denied, eparse_get_user_request_by_login_exception}
	end.

seconds_since_epoch(Diff) ->
    {Mega, Secs, _} = os:timestamp(),
    Mega * 1000000 + Secs + Diff.


list_map_to_list_tuple(List) -> list_map_to_list_tuple(List, []).

list_map_to_list_tuple([], Result) -> Result;	
list_map_to_list_tuple([Map|MapT], Result) ->	
	L = maps:to_list(Map),
	list_map_to_list_tuple(MapT, [L | Result]).


list_tuple_to_list_map(List) -> list_tuple_to_list_map(List, []).

list_tuple_to_list_map([], Result) -> lists:reverse(Result);	
list_tuple_to_list_map([H|T], Result) ->	
	list_tuple_to_list_map(T, [maps:from_list(H) | Result]).


-spec parse_ldap_name(binary()) -> {ok, cn | uid, binary(), binary()} | {error, einvalid_name}.
parse_ldap_name(undefined) -> {error, einvalid_name};	
parse_ldap_name(<<>>) -> {error, einvalid_name};	
parse_ldap_name("") -> {error, einvalid_name};	
parse_ldap_name(Name) when is_list(Name) -> 	
	parse_ldap_name(list_to_binary(Name));
parse_ldap_name(Name) -> 	
	case binary:split(Name, <<",">>) of
		[UserFilterValue, BaseFilterValue] ->
			case UserFilterValue of
				<<"cn=", Value/binary>> -> {ok, cn, Value, BaseFilterValue};
				<<"uid=", Value/binary>> -> {ok, uid, Value, BaseFilterValue};
				_ -> {error, einvalid_name}
			end;
		[UserFilterValue] ->
			case UserFilterValue of
				<<"cn=", Value/binary>> -> {ok, cn, Value, <<>>};
				<<"uid=", Value/binary>> -> {ok, uid, Value, <<>>};
				Value -> {ok, other, Value, <<>>}
			end;
		_ -> {error, einvalid_name}
	end.


parse_ldap_filter_field_and_value(Field, FieldValue) ->
	case ldap_attribute_map_to_user_field(Field) of
		{ok, FieldUser} -> 
			FieldsTable =  mnesia:table_info(user_db, attributes),
			FieldPos = ems_db:field_position(FieldUser, FieldsTable, 2),
			FieldType = ems_schema:get_data_type_field(user, FieldPos),
			case is_value_field_type(FieldValue, FieldType) of
				true -> {ok, FieldUser};
				false -> {error, einvalid_fieldtype}
			end;
		Error -> Error
	end.

parse_ldap_filter_or([], Result) -> {ok, {'or', lists:usort(Result)}};
parse_ldap_filter_or([{substrings,
                           {'SubstringFilter', Field,
                            [{any, Value}]}}|T], Result) ->
	case parse_ldap_filter_field_and_value(Field, Value) of
		{ok, Field2} -> parse_ldap_filter_or(T, [{Field2, <<"==">>, Value} | Result]);
		Error -> Error
	end;
parse_ldap_filter_or([{present, _}|T], Result) ->
	parse_ldap_filter_or(T, Result);
parse_ldap_filter_or([{equalityMatch, {'AttributeValueAssertion', Field, Value}}|T], Result) ->
	case parse_ldap_filter_field_and_value(Field, Value) of
		{ok, Field2} -> parse_ldap_filter_or(T, [{Field2, <<"==">>, Value} | Result]);
		Error -> Error
	end;
parse_ldap_filter_or(_, _) -> {error, einvalid_filter}.

parse_ldap_filter_and([], Result) -> {ok, {'and', lists:usort(Result)}};
parse_ldap_filter_and([{substrings,
                           {'SubstringFilter', Field,
                            [{any, Value}]}}|T], Result) ->
	case parse_ldap_filter_field_and_value(Field, Value) of
		{ok, Field2} -> parse_ldap_filter_and(T, [{Field2, <<"==">>, Value} | Result]);
		Error -> Error
	end;
parse_ldap_filter_and([{present, _}|T], Result) ->
	parse_ldap_filter_and(T, Result);
parse_ldap_filter_and([{equalityMatch, {'AttributeValueAssertion', Field, Value}}|T], Result) ->
	case parse_ldap_filter_field_and_value(Field, Value) of
		{ok, Field2} -> parse_ldap_filter_and(T, [{Field2, <<"==">>, Value} | Result]);
		Error -> Error
	end;
parse_ldap_filter_and([{'or', LdapFilter}|T], Result) ->
	case parse_ldap_filter_or(LdapFilter, []) of
		{ok, Condition} -> parse_ldap_filter_and(T, [Condition | Result]);
		Error -> Error
	end;
parse_ldap_filter_and(_, _) -> {error, einvalid_filter}.


-spec parse_ldap_filter(tuple()) -> {ok, list(tuple())} | {error, einvalid_filter}.
parse_ldap_filter({'or', LdapFilter}) ->
	parse_ldap_filter_or(LdapFilter, []);
parse_ldap_filter({'and', LdapFilter}) ->
	parse_ldap_filter_and(LdapFilter, []);
parse_ldap_filter(_) -> {error, einvalid_filter}.
	

-spec ldap_attribute_map_to_user_field(binary()) -> binary().
ldap_attribute_map_to_user_field(Field) -> 
	ldap_attribute_map_to_user_field_(list_to_binary(string:to_lower(binary_to_list(Field)))).
ldap_attribute_map_to_user_field_(<<"uid">>) -> {ok, <<"id">>};
ldap_attribute_map_to_user_field_(<<"employeenumber">>) -> {ok, <<"id">>};
ldap_attribute_map_to_user_field_(<<"uidnumber">>) -> {ok, <<"id">>};
ldap_attribute_map_to_user_field_(<<"gecos">>) -> {ok, <<"name">>};
ldap_attribute_map_to_user_field_(<<"displayname">>) -> {ok, <<"name">>};
ldap_attribute_map_to_user_field_(<<"distinguishedname">>) -> {ok, <<"login">>};
ldap_attribute_map_to_user_field_(<<"cn">>) -> {ok, <<"login">>};
ldap_attribute_map_to_user_field_(<<"sn">>) -> {ok, <<"name">>};
ldap_attribute_map_to_user_field_(<<"name">>) -> {ok, <<"name">>};
ldap_attribute_map_to_user_field_(<<"codigo">>) -> {ok, <<"codigo">>};
ldap_attribute_map_to_user_field_(<<"login">>) -> {ok, <<"login">>};
ldap_attribute_map_to_user_field_(<<"email">>) -> {ok, <<"email">>};
ldap_attribute_map_to_user_field_(<<"mail">>) -> {ok, <<"email">>};
ldap_attribute_map_to_user_field_(<<"cpf">>) -> {ok, <<"cpf">>};
ldap_attribute_map_to_user_field_(<<"bairro">>) -> {ok, <<"bairro">>};
ldap_attribute_map_to_user_field_(<<"cidade">>) -> {ok, <<"cidade">>};
ldap_attribute_map_to_user_field_(<<"endereco">>) -> {ok, <<"endereco">>};
ldap_attribute_map_to_user_field_(<<"complemento_endereco">>) -> {ok, <<"complemento_endereco">>};
ldap_attribute_map_to_user_field_(<<"uf">>) -> {ok, <<"uf">>};
ldap_attribute_map_to_user_field_(<<"cep">>) -> {ok, <<"cep">>};
ldap_attribute_map_to_user_field_(<<"rg">>) -> {ok, <<"rg">>};
ldap_attribute_map_to_user_field_(<<"active">>) -> {ok, <<"active">>};
ldap_attribute_map_to_user_field_(<<"datanascimento">>) -> {ok, <<"data_nascimento">>};
ldap_attribute_map_to_user_field_(<<"sexo">>) -> {ok, <<"sexo">>};
ldap_attribute_map_to_user_field_(<<"telefone">>) -> {ok, <<"telefone">>};
ldap_attribute_map_to_user_field_(<<"celular">>) -> {ok, <<"celular">>};
ldap_attribute_map_to_user_field_(<<"ddd">>) -> {ok, <<"ddd">>};
ldap_attribute_map_to_user_field_(<<"nome_pai">>) -> {ok, <<"nome_pai">>};
ldap_attribute_map_to_user_field_(<<"nome_mae">>) -> {ok, <<"nome_mae">>};
ldap_attribute_map_to_user_field_(<<"nacionalidade">>) -> {ok, <<"nacionalidade">>};
ldap_attribute_map_to_user_field_(<<"type">>) -> {ok, <<"type">>};
ldap_attribute_map_to_user_field_(<<"subtype">>) -> {ok, <<"subtype">>};
ldap_attribute_map_to_user_field_(<<"type_email">>) -> {ok, <<"type_email">>};
ldap_attribute_map_to_user_field_(<<"ctrl_insert">>) -> {ok, <<"ctrl_insert">>};
ldap_attribute_map_to_user_field_(<<"ctrl_update">>) -> {ok, <<"ctrl_update">>};
ldap_attribute_map_to_user_field_(<<"ctrl_modified">>) -> {ok, <<"ctrl_modified">>};
ldap_attribute_map_to_user_field_(<<"ctrl_last_login">>) -> {ok, <<"ctrl_last_login">>};
ldap_attribute_map_to_user_field_(<<"ctrl_login_count">>) -> {ok, <<"ctrl_login_count">>};
ldap_attribute_map_to_user_field_(<<"givenname">>) -> {ok, <<"name">>};
ldap_attribute_map_to_user_field_(<<"memberuid">>) -> {ok, <<"id">>};
ldap_attribute_map_to_user_field_(<<"member">>) -> {ok, <<"name">>};
ldap_attribute_map_to_user_field_(<<"samaccountname">>) -> {ok, <<"name">>};
ldap_attribute_map_to_user_field_(_) -> {error, einvalid_field}.



         
-spec parse_ldap_attributes(list(binary())) -> list(binary()).             
parse_ldap_attributes([]) -> [];
parse_ldap_attributes([<<"objectclass">>]) -> [];
parse_ldap_attributes([<<"objectClass">>]) -> [];
parse_ldap_attributes(List) -> 
	List2 = [ list_to_binary(string:to_lower(binary_to_list(R))) || R <- List ],
	parse_ldap_attributes_(List2, []).

parse_ldap_attributes_([], Result) -> lists:usort(Result);
parse_ldap_attributes_([<<"uid">>|T], Result) -> 
	parse_ldap_attributes_(T, [ <<"uid">> | Result]);
parse_ldap_attributes_([<<"employeenumber">>|T], Result) -> 
	parse_ldap_attributes_(T, [ <<"employeeNumber">> | Result]);
parse_ldap_attributes_([<<"uidnumber">>|T], Result) -> 
	parse_ldap_attributes_(T, [ <<"uidNumber">> | Result]);
parse_ldap_attributes_([<<"distinguishedname">>|T], Result) -> 
	parse_ldap_attributes_(T, [ <<"distinguishedName">> | Result]);
parse_ldap_attributes_([<<"gecos">>|T], Result) -> 
	parse_ldap_attributes_(T, [ <<"gecos">> | Result]);
parse_ldap_attributes_([<<"cn">>|T], Result) -> 
	parse_ldap_attributes_(T, [ <<"cn">> | Result]);
parse_ldap_attributes_([<<"givenname">>|T], Result) -> 
	parse_ldap_attributes_(T, [ <<"givenName">> | Result]);
parse_ldap_attributes_([<<"memberuid">>|T], Result) -> 
	parse_ldap_attributes_(T, [ <<"memberUid">> | Result]);
parse_ldap_attributes_([<<"member">>|T], Result) -> 
	parse_ldap_attributes_(T, [ <<"member">> | Result]);
parse_ldap_attributes_([<<"samaccountname">>|T], Result) -> 
	parse_ldap_attributes_(T, [ <<"sAMAccountName">> | Result]);
parse_ldap_attributes_([<<"displayname">>|T], Result) -> 
	parse_ldap_attributes_(T, [ <<"displayName">> | Result]);
parse_ldap_attributes_([<<"sn">>|T], Result) -> 
	parse_ldap_attributes_(T, [ <<"sn">> | Result]);
parse_ldap_attributes_([<<"creatorsname">>|T], Result) -> 
	parse_ldap_attributes_(T, [ <<"creatorsName">> | Result]);
parse_ldap_attributes_([<<"namingcontexts">>|T], Result) -> 
	parse_ldap_attributes_(T, [ <<"namingContexts">> | Result]);
parse_ldap_attributes_([<<"o">>|T], Result) -> 
	parse_ldap_attributes_(T, [ <<"o">> | Result]);
parse_ldap_attributes_([<<"mail">>|T], Result) -> 
	parse_ldap_attributes_(T, [ <<"mail">> | Result]);
parse_ldap_attributes_([<<"email">>|T], Result) -> 
	parse_ldap_attributes_(T, [ <<"email">> | Result]);
parse_ldap_attributes_([<<"codigo">>|T], Result) -> 
	parse_ldap_attributes_(T, [ <<"codigo">> | Result]);
parse_ldap_attributes_([<<"login">>|T], Result) -> 
	parse_ldap_attributes_(T, [ <<"login">> | Result]);
parse_ldap_attributes_([<<"name">>|T], Result) -> 
	parse_ldap_attributes_(T, [ <<"name">> | Result]);
parse_ldap_attributes_([<<"cpf">>|T], Result) -> 
	parse_ldap_attributes_(T, [ <<"cpf">> | Result]);
parse_ldap_attributes_([<<"passwd">>|T], Result) -> 
	parse_ldap_attributes_(T, [ <<"passwd">> | Result]);
parse_ldap_attributes_([<<"roles">>|T], Result) -> 
	parse_ldap_attributes_(T, [ <<"roles">> | Result]);
parse_ldap_attributes_([<<"roleoccupant">>|T], Result) -> 
	parse_ldap_attributes_(T, [ <<"roles">> | Result]);
parse_ldap_attributes_([<<"active">>|T], Result) -> 
	parse_ldap_attributes_(T, [ <<"active">> | Result]);
parse_ldap_attributes_([<<"endereco">>|T], Result) -> 
	parse_ldap_attributes_(T, [ <<"endereco">> | Result]);
parse_ldap_attributes_([<<"complemento_endereco">>|T], Result) -> 
	parse_ldap_attributes_(T, [ <<"complemento_endereco">> | Result]);
parse_ldap_attributes_([<<"bairro">>|T], Result) -> 
	parse_ldap_attributes_(T, [ <<"bairro">> | Result]);
parse_ldap_attributes_([<<"cidade">>|T], Result) -> 
	parse_ldap_attributes_(T, [ <<"cidade">> | Result]);
parse_ldap_attributes_([<<"uf">>|T], Result) -> 
	parse_ldap_attributes_(T, [ <<"uf">> | Result]);
parse_ldap_attributes_([<<"cep">>|T], Result) -> 
	parse_ldap_attributes_(T, [ <<"cep">> | Result]);
parse_ldap_attributes_([<<"rg">>|T], Result) -> 
	parse_ldap_attributes_(T, [ <<"rg">> | Result]);
parse_ldap_attributes_([<<"datanascimento">>|T], Result) -> 
	parse_ldap_attributes_(T, [ <<"dataNascimento">> | Result]);
parse_ldap_attributes_([<<"sexo">>|T], Result) -> 
	parse_ldap_attributes_(T, [ <<"sexo">> | Result]);
parse_ldap_attributes_([<<"telefone">>|T], Result) -> 
	parse_ldap_attributes_(T, [ <<"telefone">> | Result]);
parse_ldap_attributes_([<<"celular">>|T], Result) -> 
	parse_ldap_attributes_(T, [ <<"celular">> | Result]);
parse_ldap_attributes_([<<"ddd">>|T], Result) -> 
	parse_ldap_attributes_(T, [ <<"ddd">> | Result]);
parse_ldap_attributes_([<<"nome_pai">>|T], Result) -> 
	parse_ldap_attributes_(T, [ <<"nome_pai">> | Result]);
parse_ldap_attributes_([<<"nome_mae">>|T], Result) -> 
	parse_ldap_attributes_(T, [ <<"nome_mae">> | Result]);
parse_ldap_attributes_([<<"nacionalidade">>|T], Result) -> 
	parse_ldap_attributes_(T, [ <<"nacionalidade">> | Result]);
parse_ldap_attributes_([<<"type">>|T], Result) -> 
	parse_ldap_attributes_(T, [ <<"type">> | Result]);
parse_ldap_attributes_([<<"subtype">>|T], Result) -> 
	parse_ldap_attributes_(T, [ <<"subtype">> | Result]);
parse_ldap_attributes_([<<"type_email">>|T], Result) -> 
	parse_ldap_attributes_(T, [ <<"type_email">> | Result]);
parse_ldap_attributes_([<<"ctrl_insert">>|T], Result) -> 
	parse_ldap_attributes_(T, [ <<"ctrl_insert">> | Result]);
parse_ldap_attributes_([<<"ctrl_update">>|T], Result) -> 
	parse_ldap_attributes_(T, [ <<"ctrl_update">> | Result]);
parse_ldap_attributes_([<<"supportedcapabilities">>|T], Result) -> 
	parse_ldap_attributes_(T, [ <<"supportedCapabilities">> | Result]);
parse_ldap_attributes_([<<"supportedcontrol">>|T], Result) -> 
	parse_ldap_attributes_(T, [ <<"supportedControl">> | Result]);
parse_ldap_attributes_([<<"supportedextension">>|T], Result) -> 
	parse_ldap_attributes_(T, [ <<"supportedExtension">> | Result]);
parse_ldap_attributes_([<<"supportedfeatures">>|T], Result) -> 
	parse_ldap_attributes_(T, [ <<"supportedFeatures">> | Result]);
parse_ldap_attributes_([<<"supportedldapversion">>|T], Result) -> 
	parse_ldap_attributes_(T, [ <<"supportedLdapVersion">> | Result]);
parse_ldap_attributes_([<<"supportedSASLmechanisms">>|T], Result) -> 
	parse_ldap_attributes_(T, [ <<"supportedSASLMechanisms">> | Result]);
parse_ldap_attributes_([_|T], Result) -> 
	parse_ldap_attributes_(T, Result).

					
is_value_field_type(Value, binary_type) ->
	try
		case is_binary(Value) of
			true -> true;
			false ->
				case is_list(Value) of
					true -> true;
					false -> 
						case is_integer(Value) of
							true -> true;
							false -> false
						end
				end
		end
	catch 
		_Exception:_Reason -> false
	end;
is_value_field_type(Value, string_type) ->
	try
		case is_list(Value) of
			true -> true;
			false ->
				case is_binary(Value) of
					true -> true;
					false -> 
						case is_integer(Value) of
							true -> true;
							false -> false
						end
				end
		end
	catch 
		_Exception:_Reason -> false
	end;
is_value_field_type(Value, non_neg_integer_type) ->
	try
		case is_integer(Value) of
			true -> true;
			false ->
				case is_binary(Value) of
					true -> true;
					false -> 
						case is_list(Value) of
							true -> true;
							false -> false
						end
				end
		end
	catch 
		_Exception:_Reason -> false
	end;
is_value_field_type(Value, boolean_type) -> ems_util:parse_bool(Value);
is_value_field_type(_, _) -> false.
					

-spec get_host_list() -> binary().
get_host_list() ->
	case net_adm:host_file() of 
		{error, enoent} -> 
			list_to_binary(net_adm:localhost()); 
		Hosts -> 
			Hosts2 = [atom_to_list(R) || R <- Hosts],
			list_to_binary(lists:flatten(lists:join(",", Hosts2)))
	end.


-spec list_to_integer_def(list(), integer() | undefined) -> integer().
list_to_integer_def(S, Default) ->
	try
		list_to_integer(S)
	catch
		_:_ -> Default
	end.

-spec binary_to_integer_def(binary(), integer() | undefined) -> integer().
binary_to_integer_def(B, Default) ->
	try
		binary_to_integer(B)
	catch
		_:_ -> Default
	end.

-spec get_param_or_variable(binary(), list(map()), any()) -> any().
get_param_or_variable(ParamName, ParamsMap, DefaultValue) ->
	case maps:is_key(ParamName, ParamsMap) of
		true ->
			maps:get(ParamName, ParamsMap);
		false ->
			Result1 = DefaultValue,				
			ParanNameStr = binary_to_list(ParamName),
			case os:getenv(ParanNameStr) of % variável de ambiente em minúsculo, igual ao parâmetro
				false -> 
					case os:getenv(string:to_upper(ParanNameStr)) of % variável de ambiente em maiúsculo, padrão Linux
						false -> Result1;
						Result2 -> list_to_binary(Result2)
					end;
				Result2 -> list_to_binary(Result2)
			end
	end.

-spec get_environment_variable(binary() | string()) -> binary().
get_environment_variable(ParamName) -> get_environment_variable(ParamName, <<>>).

-spec get_environment_variable(binary() | string(), any()) -> binary().
get_environment_variable(ParamNameBin, DefaultValue) when is_binary(ParamNameBin) ->
	get_environment_variable(binary_to_list(ParamNameBin), DefaultValue);
get_environment_variable(ParanNameStr, DefaultValue) ->
	case os:getenv(ParanNameStr) of % variável de ambiente em minúsculo, igual ao parâmetro
		false -> 
			case os:getenv(string:to_upper(ParanNameStr)) of % variável de ambiente em maiúsculo, padrão Linux
				false -> 
					case is_binary(DefaultValue) of
						true -> DefaultValue;
						false -> list_to_binary(DefaultValue)
					end;
				Result2 -> list_to_binary(Result2)
			end;
		Result -> list_to_binary(Result)
	end.


format_rest_status(Code, Reason, ReasonDetail, ReasonException, Latency) ->
   iolist_to_binary([
		integer_to_binary(Code), 
		<<" <<">>, case is_atom(Reason) of
						true -> 
						   case ReasonDetail =/= undefined andalso is_atom(ReasonDetail) of
								true ->
								   case ReasonException =/= undefined andalso is_atom(ReasonException) of
										true -> [atom_to_binary(Reason, utf8), <<", ">>, atom_to_binary(ReasonDetail, utf8), <<", ">>, atom_to_binary(ReasonException, utf8)];
										false -> [atom_to_binary(Reason, utf8), <<", ">>, atom_to_binary(ReasonDetail, utf8)]
								   end;
								false -> atom_to_binary(Reason, utf8)
						   end;
						false -> <<"error">>
				  end, <<">> (">>, integer_to_binary(Latency), 
		<<"ms)">>]).
				  

get_free_tcp_port() ->
	{ok, Listen} = gen_tcp:listen(0, [{keepalive, false}, {exit_on_close, true}]),
	Port = inet:port(Listen),
	gen_tcp:close(Listen),
	Port.


-spec get_pid_from_port(non_neg_integer()) -> {ok, non_neg_integer()} | {error, enoent}.
get_pid_from_port(Port) ->
	try
		case lists:reverse(os:cmd(io_lib:format("lsof -i:~p -t", [Port]))) of
			"\n" ++ PidStr -> {ok, list_to_integer(lists:reverse(PidStr))};
			_ -> {error, enoent}
		end
	catch
		_:Reason -> 
			ems_logger:error("ems_util get_pid_from_port failed with port ~p. Reason: ~p.", [Port, Reason]),
			{error, enoent}
	end.
	

-spec os_command(string()) -> {ok, any()} | {error, einvalid_command}.
os_command(Cmd) -> os_command(Cmd, undefined).
	
-spec os_command(string(), list()) -> {ok, any()} | {error, einvalid_command}.
os_command(Cmd, Options) when is_binary(Cmd) ->
	os_command(binary_to_list(Cmd), Options);
os_command(Cmd, Options) ->
	try
		case Options == undefined orelse Options == [] of
			true -> Result = os:cmd(Cmd);
			false -> Result = os:cmd(Cmd, Options)
		end,
		{ok, Result}
	catch
		_:undef -> 
			% na versão 21 em diante é que existe a função os:cmd com arity 2
			os_command(Cmd, undefined);
		_:Reason -> 
			ems_logger:error("ems_util os_command execute failed: ~p. Reason: ~p.", [Cmd, Reason]),
			{error, einvalid_command}
	end.

-spec get_java_home() -> string().
get_java_home() -> remove_ult_backslash_url(binary_to_list(ems_util:get_environment_variable(<<"JAVA_HOME">>))).

-spec integer_to_list_def(string(), string()) -> string().
integer_to_list_def(Value, Default) ->
	try
		integer_to_list(Value)
	catch
		_:_ ->	Default
	end.
	
-spec str_trim(string()) -> string().
str_trim(S) -> 
	case erlang:system_info(otp_release) of
		"19" -> string:strip(S);
		_ -> string:trim(S)
	end.

-spec binary_to_hex(binary()) -> binary().
binary_to_hex(Bin) when is_binary(Bin) ->
    << <<(hex(H)),(hex(L))>> || <<H:4,L:4>> <= Bin >>.

hex(C) when C < 10 -> $0 + C;
hex(C) -> $a + C - 10.

% Return a encrypted password in binary format        
criptografia_sha1(<<>>) -> <<>>;
criptografia_sha1("") -> <<>>;	
criptografia_sha1(undefined) -> <<>>;
criptografia_sha1(null) -> <<>>;
criptografia_sha1(Password) when is_binary(Password) -> 
	criptografia_sha1(binary_to_list(Password));
criptografia_sha1(Password) -> base64:encode(sha1:binstring(Password)).

% Return a encrypted password in binary format        
criptografia_md5(<<>>) -> <<>>;
criptografia_md5("") -> <<>>;	
criptografia_md5(undefined) -> <<>>;
criptografia_md5(null) -> <<>>;
criptografia_md5(Password) when is_binary(Password) -> 
	criptografia_md5(binary_to_list(Password));
criptografia_md5(Password) -> binary_to_hex(crypto:hash(md5, Password)).

criptografia_blowfish(Password) -> ems_blowfish:criptografia(Password).


-spec flush_messages() -> ok.
flush_messages() ->
	receive
	_ -> 
		flush_messages()
	after 500 ->
		ok
	end.

-spec str_contains(string(), list(string())) -> boolean().
str_contains(_, []) -> false;
str_contains(Str, [H|T]) ->
	case string:str(Str, H) > 0 of
		true -> true;
		false -> str_contains(Str, T)
	end.
	

oauth2_authenticate_rest_server(RestAuthUrl, RestUser, RestPasswd) ->
	GrantQuery = binary_to_list(iolist_to_binary([<<"grant_type=password&username=">>, RestUser, <<"&password=">>, RestPasswd])),
	case httpc:request(post, {[RestAuthUrl], [], "application/x-www-form-urlencoded", GrantQuery}, [], []) of
		{ok, {_, _, ResultAuthPayload}} -> 
			case ems_util:json_decode_as_map(list_to_binary(ResultAuthPayload)) of
				{ok, ResultAuthPayloadMap} -> 
					case maps:is_key(<<"error">>, ResultAuthPayloadMap) of
						true -> 
							{ok, <<>>};
						false -> 
							AccessToken = maps:get(<<"access_token">>, ResultAuthPayloadMap, undefined),
							case AccessToken of
								undefined -> {ok, <<>>};
								_ -> {ok, AccessToken}
							end
					end;
				_ ->
					{error, eunavailable_rest_server}
			end;
		_ -> 
			{error, eunavailable_rest_server}
	end.


-spec binary_to_list_def(binary(), string()) -> string().
binary_to_list_def(undefined, Default) -> Default;
binary_to_list_def(null, Default) -> Default;
binary_to_list_def(<<>>, Default) -> Default;
binary_to_list_def(Value, Default) ->
	try
		binary_to_list(Value)
	catch
		_:_ -> Default
	end.

-spec parse_to_integer(any()) -> integer().
parse_to_integer(undefined) -> undefined;
parse_to_integer(V) when is_binary(V) -> binary_to_integer(V);
parse_to_integer(V) when is_list(V) -> list_to_integer(V);
parse_to_integer(V) when is_integer(V) -> V;
parse_to_integer(_) -> erlang:error(einvalid_integer).

-spec file_writable(string() | binary()) -> boolean().
file_writable(Filename) when is_binary(Filename) ->
	file_writable(binary_to_list(Filename));
file_writable(Filename) ->
	case file:read_file_info(Filename) of
		{ok,{file_info,_,regular,read_write,
               _,
               _,
               _,
               _,_,_,_,_,_,_}} -> true;
         _ -> false
     end.

-spec path_writable(string() | binary()) -> boolean().
path_writable(Pathname) when is_binary(Pathname) ->
	path_writable(binary_to_list(Pathname));
path_writable(Pathname) ->
	case file:read_file_info(Pathname) of
		{ok,{file_info,_,directory,read_write,
               _,
               _,
               _,
               _,_,_,_,_,_,_}} -> true;
         _ -> false
     end.

-spec ensure_dir_writable(string()) -> ok  | {error, atom()}.
ensure_dir_writable(Path) ->
	case file:make_dir(Path) of
		ok -> ok;
		{error, eexist} -> ok;
		_ -> filelib:ensure_dir(Path)
	end,
	case path_writable(Path) of
		true -> ok;
		false -> {error, denied}
	end.

-spec file_exists(string()) -> boolean().
file_exists(undefined) -> false;
file_exists("") -> false;
file_exists(Filename) ->
	file:read_file_info(Filename) =/= {error,enoent}.

-spec is_production_server() -> boolean().
is_production_server() -> ems_db:get_param(instance_type) == production.
