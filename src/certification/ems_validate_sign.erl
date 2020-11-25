-module(ems_validate_sign).

-export([execute/1,validate/1]).


-include_lib("xmerl/include/xmerl.hrl").
-include_lib("public_key/include/public_key.hrl").
-include("../include/ems_schema.hrl").


execute(Request) -> 
    io:format("Entrou aqui >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> ~n~n"),
    FileXml = esaml_util:read_file_xml("/home/renato/Downloads/desenvolvimento/cpd/git/certificado/test_signed/original.xml"),
    io:format("Entrou aqui 2 >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> ~n~n"),
    validate(FileXml),
    io:format("Entrou aqui 3 >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> ~n~n"),
    {ok, Request#request{code = 200,
            content_type_out = <<"application/json">>,
            response_data = <<"{\"response\" : \" Work correctlly!\"}">>}
	}.


validate(FileXml) ->
    XsdDir = filename:dirname("/home/renato/Downloads/desenvolvimento/cpd/git/certificado/test_signed/leiauteDiplomaDigital.xsd"),
    {ok, State} = erlsom:compile_xsd_file("/home/renato/Downloads/desenvolvimento/cpd/git/certificado/test_signed/leiauteDiplomaDigital.xsd", 
        [{include_dirs, [XsdDir]}]),
    {Entity ,_} = xmerl_scan:file("/home/renato/Downloads/desenvolvimento/cpd/git/certificado/test_signed/original.xml"),
    io:format("Entrou aqui validate 3 >>>>>>>>>>>>>>>>>>>>>> ~n~n"),
    %%Result = xmerl_xsd:validate(Entity, State),
    {ok, Result, _} = erlsom:scan_file(Entity, State),
    io:format("Result >>>>>>>>>>>>>>>>>>>>>>> ~p~n~n",[Result]).
