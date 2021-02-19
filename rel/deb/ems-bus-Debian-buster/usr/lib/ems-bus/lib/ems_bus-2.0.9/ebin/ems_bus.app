%% coding: utf-8
%% app generated at {2021,2,17} {15,10,54}
{application,ems_bus,
             [{description,"ErlangMS"},
              {vsn,"2.0.9"},
              {id,[]},
              {modules,['LDAP',correios_client,correios_server,ems_api_query,
                        ems_api_query_db2,ems_api_query_db2_parse,
                        ems_api_query_mnesia,ems_api_query_mnesia_parse,
                        ems_api_query_odbc,ems_api_query_postgresql,
                        ems_api_query_postgresql_parse,ems_api_query_service,
                        ems_api_query_sqlite,ems_api_query_sqlserver,
                        ems_api_query_sqlserver_parse,ems_api_query_validator,
                        ems_auth_user,ems_barramento_service,ems_bus,
                        ems_bus_app,ems_bus_sup,ems_cache,ems_catalog,
                        ems_catalog_loader_middleware,ems_catalog_lookup,
                        ems_catalog_middleware,ems_catalog_owner_middleware,
                        ems_catalog_schema,ems_catalog_schema_middleware,
                        ems_catalog_schema_service,ems_client,
                        ems_client_loader_middleware,ems_clock,
                        ems_cmd_service,ems_config,ems_cripto_sign,
                        ems_daemon_service,ems_data_loader,
                        ems_data_loader_ctl,ems_data_loader_service,
                        ems_data_pump,ems_db,ems_dispatcher,ems_eventmgr,
                        ems_file_watcher,ems_http_handler,ems_http_listener,
                        ems_http_server,ems_info_service,ems_json_loader,
                        ems_json_scan,ems_ldap_handler,ems_ldap_listener,
                        ems_ldap_server,ems_logger,ems_logger_os_service,
                        ems_logger_service,ems_netadm_service,
                        ems_oauth2_authorize,ems_oauth2_backend,
                        ems_oauth2_recurso,ems_odbc_pool,ems_odbc_pool_worker,
                        ems_pool,ems_redirect_url_service,ems_schema,
                        ems_stat_collector,ems_static_file_service,
                        ems_upload_file_service,ems_user,
                        ems_user_dados_funcionais,
                        ems_user_dados_funcionais_loader_middleware,
                        ems_user_email,ems_user_email_loader_middleware,
                        ems_user_endereco,ems_user_endereco_loader_middleware,
                        ems_user_loader_middleware,ems_user_notify_service,
                        ems_user_perfil,ems_user_perfil_loader_middleware,
                        ems_user_permission,
                        ems_user_permission_loader_middleware,
                        ems_user_telefone,ems_user_telefone_loader_middleware,
                        ems_util,ems_validate_sign,ems_web_service_correios,
                        ems_websocket_handler,esaml,esaml_util,
                        helloworld_service,oauth2,oauth2_backend,
                        oauth2_config,oauth2_priv_set,oauth2_response,
                        oauth2_token,oauth2_token_generation,
                        produto_middleware,sha1,xmerl_c14n]},
              {registered,[]},
              {applications,[kernel,stdlib,odbc,asn1,crypto,public_key,ssl,
                             inets,syntax_tools,compiler,parse_trans,ranch,
                             cowlib,cowboy,json_rec,jsx,jiffy,jesse,poolboy,
                             mochiweb]},
              {included_applications,[]},
              {env,[{oauth2,[{expiry_time,3600},
                             {backend,oauth2ems_backend},
                             {password_credentials,[{expiry_time,7200}]},
                             {client_credentials,[{expiry_time,86400}]},
                             {refresh_token,[{expiry_time,2592000}]},
                             {code_grant,[{expiry_time,600}]}]}]},
              {maxT,infinity},
              {maxP,infinity},
              {mod,{ems_bus_app,[]}}]}.
