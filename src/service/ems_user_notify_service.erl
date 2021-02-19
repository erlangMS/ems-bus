%%********************************************************************
%% @title Module ems_user_notify_service
%% @version 1.0.0
%% @doc Module ems_user_notify_service
%% @author Everton de Vargas Agilar <evertonagilar@gmail.com>
%% @copyright ErlangMS Team
%%********************************************************************

-module(ems_user_notify_service).

-behaviour(gen_server).

-include("include/ems_config.hrl").
-include("include/ems_schema.hrl").

-define(SERVER, ?MODULE).


%% Server API
-export([start/1, stop/0]).

-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2, code_change/3]).

-export([add/1]).

-record(state, {users = []}).

%% API.

start(_Args) ->	gen_server:start({local, ?MODULE}, ?MODULE, [], []).

stop() -> gen_server:call(?MODULE, stop).

add(User) -> gen_server:cast(?SERVER, {add_user, User}). 

%% gen_server.

-spec init([]) -> {ok, #state{}}.
init(_Service) -> {ok, #state{users = []}, 6000}.

handle_call(_Request, _From, State) ->
	{reply, ignored, State, 5000}.

handle_cast({add_user, User}, State = #state{users = Users}) ->
	State2 = State#state{users = [User | Users]},
	{noreply, State2, 1000};

handle_cast(_Msg, State) ->
	{noreply, State, 5000}.

handle_info(_Info, State = #state{users = []}) -> 
	{noreply, State, 3000};
handle_info(_Info, #state{users = Users}) ->
	Conf = ems_config:getConfig(),
	notifica_users(Conf, Users),
	{noreply, #state{users = []}, 100}.

-spec terminate(_, _) -> ok.
terminate(_Reason, _State) ->
	ok.

-spec code_change(_, State, _) -> {ok, State}.
code_change(_OldVsn, State, _Extra) ->
	{ok, State}.


notifica_users_message(Conf, Buffer) ->
	try
		UserListJson = ems_schema:to_json(Buffer),
		MsgService = {{0, "/netadm/dataloader/user/notify", "POST", #{}, #{}, 
						UserListJson, % Payload
						<<"application/json">>,  
						atom_to_list(Conf#config.java_service_user_notify_module),
						Conf#config.java_service_user_notify_function,  	% FunctionName
						<<>>,  		 	% ClientJson
						<<>>,  		 	%UserJson, 
						<<>>,  		 	% Metadata, 
						{<<>>, <<>>},  	% {Scope, AccessToken}, 
						0, 			 	% T2, 
						0 			 	% Timeout
						}, self()},
		Node = Conf#config.java_service_user_notify_node,  %Ex.: 'br_unb_pessoal_facade_AtualizaDadosSIPFacade_node01@CPD-DES-374405'
		Module = Conf#config.java_service_user_notify_module, %Ex.: 'br.unb.pessoal.facade.AtualizaDadosSIPFacade'
		{Module, Node} ! MsgService
	catch 
		_Exception:Reason -> ems_logger:error("ems_user_notify_service send message failed. Reason: ~p.", [Reason])
	end.


notifica_users(Conf, Users) ->
	notifica_users(Conf, Users, [], 0).
	
notifica_users(Conf, [], Buffer, _) ->
	notifica_users_message(Conf, Buffer);
notifica_users(Conf, Users, Buffer, 200) ->
	notifica_users_message(Conf, Buffer),
	notifica_users(Conf, Users, [], 0);
notifica_users(Conf, [H|T], Buffer, Count) ->
	case Conf#config.log_show_user_notify_activity of
		true -> 
			ems_logger:info("ems_user_notify_service notify user name: \"~s\", login: \"~s\", cpf: \"~s\" email: \"~s\",  nome_mae: \"~s\", ctrl_source_type: ~p, ctrl_modified: \"~s\".", [
					binary_to_list(H#user.name), 
					binary_to_list(H#user.login), 
					ems_util:binary_to_list_def(H#user.cpf, ""),
					ems_util:binary_to_list_def(H#user.email, ""), 
					ems_util:binary_to_list_def(H#user.nome_mae, ""),
					H#user.ctrl_source_type,
					ems_util:binary_to_list_def(H#user.ctrl_modified, "")]);
		false -> ok
	end,
	notifica_users(Conf, T, [H | Buffer], Count+1).

