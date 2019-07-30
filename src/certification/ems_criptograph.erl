-module(ems_criptograph).

-include("../include/ems_schema.hrl").
-include_lib("xmerl/include/xmerl.hrl").

-export([read_private_key/1, read_public_key/1, read_certificate/1 ,read_pdf/1, execute/1, verify_sign/3, read_xml/1, digest/3, sign_document_xades/2]).



execute(Request) -> 
   
    PrivateKey = read_private_key("/media/renato/SSD/desenvolvimento/barramento/certificado/ems-bus/src/certification/private.pem"),
    Certificate = read_certificate("/media/renato/SSD/desenvolvimento/certificado/client.crt"),
    PDF = read_pdf("/home/renato/Downloads/file.pdf"),
    ListFilesAuthorities = read_all_files_path("/media/renato/SSD/desenvolvimento/certificado/autoridades"),
    sign_pdf(PrivateKey, PDF),
    PublicKey = read_public_key("/media/renato/SSD/desenvolvimento/barramento/certificado/ems-bus/src/certification/public.pem"),
    Verified = verify_sign(PDF, "/media/renato/SSD/desenvolvimento/barramento/certificado/ems-bus/src/certification/fileSign", PublicKey),
    sign_document_xades(PrivateKey,read_xml("/media/renato/SSD/desenvolvimento/certificado/diplomas/diploma.xml")),
    
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

sign_xml(PrivKey, Msg) -> 
    DigestType = sha256,
    SigBin = public_key:sign(Msg, DigestType, PrivKey),
    SigBinBase64 = base64:encode(SigBin),
    SigBinNotString1 = re:replace(SigBinBase64, "<<\"","",[global, {return, list}]),
    re:replace(SigBinNotString1, "\">>","",[global, {return, list}]).
    

sign_document_xades(PrivKey, Xml) ->
    {ok, Data, _Unused} = erlsom:simple_form_file("/media/renato/SSD/desenvolvimento/certificado/diplomas/diploma.xml"),
    XmlUpdated = tuple_to_list(Data),
    Atributes = create_xml_sign(XmlUpdated, []),
    Result = create_atributes_xml(Atributes,[]),
    %%TODO: Adicionar a assinatura neste ponto
    
    SignedXml = sign_xml(PrivKey, ems_util:open_file("/media/renato/SSD/desenvolvimento/certificado/diplomas/diploma.xml")),
    Result2 = string:concat("<?xml version=\"1.0\" encoding=\"UTF-8\"?><CertificadoExtensao>",Result),

    %%TODO: Adicionar o XML de validação do XML
    %%term_to_binary() base64:encode(X)
    XmlSign = part_xml_signed(),
    FileWithXmlSign = string:concat(Result2, XmlSign),
    Digest =  digest(XmlUpdated, sha256, FileWithXmlSign),
    SignatureValue = insert_ds_signature(SignedXml, Digest),  
    ResultFinal = string:concat(SignatureValue, "</CertificadoExtensao>"),
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




digest(Data, HashFunction, XmlWithSign) ->
    Result =  crypto:hash(HashFunction, lists:flatten(io_lib:format("~p",[Data]))),
    Result2 =  base64:encode(Result),
    re:replace(XmlWithSign,"\\?\\?\\?Digest",Result2,[global, {return, list}]).


insert_ds_signature(SignBase64, XmlWithDigest) ->
   re:replace(XmlWithDigest, "\\?\\?\\?SignaturaValue", SignBase64,[global, {return, list}]).


part_xml_signed() ->
    "<ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\" Id=\"???Id\">
    <ds:SignedInfo><ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments\">
    </ds:CanonicalizationMethod><ds:SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256\">
    </ds:SignatureMethod><ds:Reference URI=\"\">
    <ds:Transforms>
    <ds:Transform Algorithm=\"http://www.w3.org/TR/1999/REC-xpath-19991116\">
    <ds:XPath>not(ancestor-or-self::ds:Signature)</ds:XPath>
    </ds:Transform></ds:Transforms>
    <ds:DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"></ds:DigestMethod>
    <ds:DigestValue>???Digest</ds:DigestValue>
    </ds:Reference></ds:SignedInfo><ds:SignatureValue>???SignaturaValue</ds:SignatureValue>
    <ds:KeyInfo><ds:X509Data><ds:X509Certificate>???X509Certificate</ds:X509Certificate>
    </ds:X509Data></ds:KeyInfo>".


