-module(ems_criptograph).

-include("../include/ems_schema.hrl").

-export([read_private_key/1, read_public_key/1, read_certificate/1 ,read_pdf/1, execute/1, verify_sign/3, read_xml/1]).



execute(Request) -> 
   
    PrivateKey = read_private_key("/media/renato/SSD/desenvolvimento/barramento/certificado/ems-bus/src/certification/private.pem"),
    Certificate = read_certificate("/media/renato/SSD/desenvolvimento/certificado/client.crt"),
    PDF = read_pdf("/home/renato/Downloads/file.pdf"),
    ListFilesAuthorities = read_all_files_path("/media/renato/SSD/desenvolvimento/certificado/autoridades"),
    sign_pdf(PrivateKey, PDF),
    PublicKey = read_public_key("/media/renato/SSD/desenvolvimento/barramento/certificado/ems-bus/src/certification/public.pem"),
    Verified = verify_sign(PDF, "/media/renato/SSD/desenvolvimento/barramento/certificado/ems-bus/src/certification/fileSign", PublicKey),
    sign_document_xades(PrivateKey,read_xml("/media/renato/SSD/desenvolvimento/certificado/diplomas/diploma.xml")),
    io:format("Funcionou o teste >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> :)"),

    {ok, Request#request{code = 200,
            content_type_out = <<"application/json">>,
            response_data = <<"{\"response:\" \" Work correctlly!\"}">>}
	}.

read_private_key(FilePrivateKey) ->
      RawSKey =  ems_util:open_file(FilePrivateKey),
      [EncSKey] = public_key:pem_decode(RawSKey),
      SKey = public_key:pem_entry_decode(EncSKey),
      SKey.
	

read_public_key(FilePublicKey) ->
        RawPKey =  ems_util:open_file(FilePublicKey),
        [EncPKey] = public_key:pem_decode(RawPKey),
        PKey = public_key:pem_entry_decode(EncPKey),
        PKey.

read_certificate(FileCertificate) ->
    ContentCert = ems_util:open_file(FileCertificate),
    [ Certificate ] = public_key:pem_decode(ContentCert),
    Cert =  public_key:pem_entry_decode(Certificate),
    Data1 = element(2, Cert),
    PublicCertificateKey =  element(8, Data1),
    {ok, PublicCertificateKey}.


read_pdf(FilePDF) ->
    ems_util:open_file(FilePDF).
 

sign_pdf(PrivKey, Msg) ->
    DigestType = sha256,
    SigBin = public_key:sign(Msg, DigestType, PrivKey),
    file:write_file("/media/renato/SSD/desenvolvimento/barramento/certificado/ems-bus/src/certification/fileSign", SigBin).


read_xml(FileXML) ->
    xmerl_scan:file(FileXML).



sign_document_xades(PrivKey, Xml) ->
    io:format("Xml >>>>>>>>>>>>>>>>>>>>>>>>>>> ~p~n~n",[Xml]),
    {ok, Data, _Unused} = erlsom:simple_form_file("/media/renato/SSD/desenvolvimento/certificado/diplomas/diploma.xml"),
    io:format("Data >>>>>>>>>>>>>>>>>>>>>>>> ~p~n~n",[Data]),
    XmlUpdated = tuple_to_list(Data),
    io:format("XmlUpdated >>>>>>>>>>>>>>>>>>>>>>>> ~p~n~n",[XmlUpdated]),
    Atributes = create_xml_sign(XmlUpdated, []),
    io:format("Atributes >>>>>>>>>>>>>>>>>>>>>>>>>> ~p~n~n",[Atributes]),
    Result = create_atributes_xml(Atributes,[]),
    %%TODO: Adicionar a assinatura neste ponto
    Result2 = string:concat("<?xml version=\"1.0\" encoding=\"UTF-8\"?><CertificadoExtensao>",Result),
    ResultFinal = string:concat(Result2, "</CertificadoExtensao>"),
    io:format("Result >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> ~p~n~n",[ResultFinal]),
    file:write_file("/media/renato/SSD/desenvolvimento/certificado/diplomas/sign_diploma.xml", ResultFinal),
    Xml.


create_xml_sign([], Acc) ->
    Acc;
create_xml_sign([H|T], Acc) ->
    create_xml_sign(T, H).


create_atributes_xml([], Acc) ->
    Acc;
create_atributes_xml([H|T], Acc) ->
   Element = create_element_xml(tuple_to_list(H),""),
    create_atributes_xml(T, Element ++ Acc).

create_element_xml([H|T], Acc) ->
    Element1 = string:concat("<",H),
    Element2 = string:concat(Element1,">"),
    Atribute2 =  lists:nth(2,T),
    StringFormat = re:replace(Atribute2,"\\["," ", [global, {return, list}]),
    StringFormat2 = re:replace(StringFormat,"\\]"," ", [global, {return, list}]),
    Element3 = string:concat(Element2,StringFormat2),
    Element4 = string:concat("</",H),
    Element5 = string:concat(Element4,">"),
    string:concat(Element3,Element5).


verify_sign(Msg, SignatureFile ,PublicKey) ->
    DigestType = sha256,
    Signature = ems_util:open_file(SignatureFile),
    public_key:verify(Msg, DigestType, Signature, PublicKey).


read_all_files_path(Dir) ->
    read_all_files_path(Dir, true).

read_all_files_path(Dir, FilesOnly) ->
    case filelib:is_file(Dir) of
        true ->
            case filelib:is_dir(Dir) of
                true -> {ok, read_all_files_path([Dir], FilesOnly, [])};
                false -> {error, enotdir}
            end;
        false -> {error, enoent}
    end.


read_all_files_path([], _FilesOnly, Acc) ->
    Acc;
read_all_files_path([Path|Paths], FilesOnly, Acc) ->
        read_all_files_path(Paths, FilesOnly,
        case filelib:is_dir(Path) of
            false -> [Path | Acc];
            true ->
                {ok, Listing} = file:list_dir(Path),
                SubPaths = [filename:join(Path, Name) || Name <- Listing],
                read_all_files_path(SubPaths, FilesOnly,
                    case FilesOnly of
                        true -> Acc;
                        false -> [Path | Acc]
                    end)
        end).


verify_valid_certificate(Certificate, ListFilesAutorities) ->
    Result = case ListFilesAutorities of
        {ok, ListFiles} -> 
             ListFiles;
        _ -> {error, invalid_format}
    end,
    iterator_list(Certificate, Result).


iterator_list(_Certificate,[]) -> 
    false;
iterator_list(Certificate,[H|T]) ->
    ContentCertificateAuthority = read_certificate(H),
    case Certificate of
        ContentCertificateAuthority -> true;
        _ ->  iterator_list(Certificate,T)
    end.

    
