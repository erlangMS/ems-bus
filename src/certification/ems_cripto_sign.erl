%% -*- coding: utf-8 -*-
%%
%% esaml - SAML for erlang
%%
%% Copyright (c) 2013, Alex Wilson and the University of Queensland
%% All rights reserved.
%%
%% Distributed subject to the terms of the 2-clause BSD license, see
%% the LICENSE file in the root of the distribution.

%% @doc XML digital signatures for xmerl
%%
%% Functions for performing XML digital signature generation and
%% verification, as specified at http://www.w3.org/TR/xmldsig-core/ .
%%
%% These routines work on xmerl data structures (see the xmerl user guide
%% for details).
%%
%% Currently only RSA + SHA1|SHA256 signatures are supported, in the typical
%% enveloped mode.
-module(ems_cripto_sign).

-export([execute/1]).
-export([verify/1]).
%%-export([verify/2]).
-export([sign/4]).
-export([strip/1]).
-export([digest/1]).

-include_lib("xmerl/include/xmerl.hrl").
-include_lib("public_key/include/public_key.hrl").
-include("../include/ems_schema.hrl").

-type xml_thing() :: #xmlDocument{} | #xmlElement{} | #xmlAttribute{} | #xmlPI{} | #xmlText{} | #xmlComment{}.
%-type sig_method() :: rsa_sha1 | rsa_sha256.
%-type sig_method_uri() :: string().
-type fingerprint() :: binary() | {sha | sha256, binary()}.

execute(Request = #request{rid = Rid,
							type = Type,
						    url = Url,
							payload = Payload,
							client = Client,
							user = User,
							scope = Scope,
							access_token = AccessToken,
							content_type_out = ContentType,  
							params_url = ParamsMap,
							querystring_map = QuerystringMap}) -> 
    Key = read_private_key("private_key.pem"),
    CertBin = read_certificate("publicCert.pem"),  
    io:format("Payload >>>>>>>>>>>>>>>>>>>>>>>>>>>> ~p~n~n",[Payload]),                          
    {ok, ListFileUnziped} = zip:unzip(Payload),
    io:format("ListFileUnziped >>>>>>>>>>>>>>>>>>>>>>>>>>>> ~p~n~n",[ListFileUnziped]),
    recursion_file_sign(length(ListFileUnziped),ListFileUnziped, Key, CertBin),
    %Doc = strip(SignedXml), 
    %ok = verify(SignedXml, [crypto:hash(sha, CertBin)]),
    {ok, Request#request{code = 200,
            content_type_out = <<"application/json">>,
            response_data = <<"{\"response\" : \" Work correctlly!\"}">>}
	}.


recursion_file_sign(0, FileUnziped, Key, CertBin) ->
    io:format("");
recursion_file_sign(N, [H|T], Key, CertBin) when N > 0 ->
    FileXml = read_file_xml(H),
    {Docs, _} = xmerl_scan:string(FileXml, [{namespace_conformant, true}]),
    SignedXml = sign(Docs, Key, rsa_sha256, CertBin),
    XmlFormater = transform_tuple_in_xml(SignedXml),
    Path = "/home/renato/Downloads/desenvolvimento/cpd/git/certificado/test_signed/signed_xml" ++ lists:flatten(io_lib:format("~p", [N])),
    Path1 = string:concat(Path,".xml"),
    create_file_signed(Path1,XmlFormater),
    recursion_file_sign(N-1, T, Key, CertBin).

%% @doc Returns an xmlelement without any ds:Signature elements that are inside it.
strip(Doc) ->
    #xmlDocument{content = Kids} = Doc,
    NewKids = [if (element(1,K) =:= xmlElement) -> 
        strip(K); true -> K end || K <- Kids],
    Doc#xmlDocument{content = NewKids};

strip(#xmlElement{content = Kids} = Elem) ->
    NewKids = lists:filter(fun(Kid) ->
        case xmerl_c14n:canon_name(Kid) of
            "http://www.w3.org/2000/09/xmldsig#Signature" -> 
                false;
            _Name ->
                true
        end
    end, Kids),
    Elem#xmlElement{content = NewKids}.

%% @doc Signs the given XML element by creating a ds:Signature element within it, returning
%%      the element with the signature added.
%%
%% Don't use "ds" as a namespace prefix in the envelope document, or things will go baaaad.
sign(ElementIn, PrivateKey, SigMethod, CertChain) ->
    [H|T] = CertChain,
    CertBin = element(2,H),
    %%ID = xmerl_xs:select("@ID", ElementIn),
    %%io:format("Element >>>>>>>>>>>>>> ~p~n~n",[element(9,lists:nth(1,ID))]),
        
    RandomNumberConcat = lists:flatten(io_lib:format("~p", [rand:uniform(10000)])),
    SignedProperties =  string:concat("SIG_PROPERTIES_",RandomNumberConcat),
    %ElementStrip = strip(ElementIn),
    % make sure the root element has an ID... if it doesn't yet, add one
    {Element, Id} = case lists:keyfind('ID', 2, ElementIn#xmlElement.attributes) of
        #xmlAttribute{value = CapId} ->
            {ElementIn, CapId};
        _ ->
            case lists:keyfind('id', 2, ElementIn#xmlElement.attributes) of
                #xmlAttribute{value = LowId} ->
                    {ElementIn, LowId};
                _ ->
                    NewId = binary_to_list(base64:encode(crypto:strong_rand_bytes(20))),
                    Attr = #xmlAttribute{name = 'Id', value = NewId, namespace = #xmlNamespace{}},
                    NewAttrs = [Attr | ElementIn#xmlElement.attributes],
                    Elem = ElementIn#xmlElement{attributes = NewAttrs},
                    {Elem, NewId}
            end
    end,

    % create a id for element ds:signature
    Target = binary_to_list(base64:encode(crypto:strong_rand_bytes(20))),
    % start create de signature elements in xades pattern
    {HashFunction, DigestMethod, SignatureMethodAlgorithm} = signature_props(SigMethod),
    % create a ds with url signature
    Ns = #xmlNamespace{nodes = [{"ds", 'http://www.w3.org/2000/09/xmldsig#'}]},
    % first we need the digest, to generate our SignedInfo element
    SigInfo = generate_sing_info_element(Element, HashFunction, SignatureMethodAlgorithm, DigestMethod, Ns, Id, SignedProperties, PrivateKey),
    SigInfoCanon = xmerl_c14n:c14n(SigInfo),
    SigElemObject =  generate_xades_sing_element(HashFunction, SigInfoCanon, Ns, Target, CertChain, SignedProperties),
    % now we sign the SignedInfo element...  
    Data = unicode:characters_to_binary(SigInfoCanon),
    Signature = public_key:sign(Data, HashFunction, PrivateKey),
    %change bin sign in base 64 sign
    Sig64 = base64:encode_to_string(Signature),
    Cert64 = base64:encode_to_string(CertBin),
    % and wrap it all up with the signature and certificate
    SigElem = generate_element_ds_signature(SigInfo,SigElemObject, Sig64, Cert64, Ns, Target),
    Element#xmlElement{content = [ SigElem | Element#xmlElement.content ]}.



generate_sing_info_element(Element, HashFunction, SignatureMethodAlgorithm, DigestMethod, Ns, Id, SignedProperties, PrivateKey) ->
    % CanonXml = xmerl_c14n:c14n(Element),
    % create a digest value. 
    DigestValue = base64:encode_to_string(digest(Element, sha256)),
    %  openssl rsa -in /home/renato/Downloads/desenvolvimento/cpd/git/certificado/certificado_fabiano/private_key.pem -pubin -outform der | openssl dgst -sha256
    DigestPrivateKey = os:cmd("openssl rsa -in /home/renato/Downloads/desenvolvimento/cpd/git/certificado/certificado_fabiano/private_key.pem -pubin -outform der | openssl dgst -sha256"),
    {_Header,Key,_Footer} = read_private_key_encoded("/home/renato/Downloads/desenvolvimento/cpd/git/certificado/certificado_fabiano/private_key.pem"),
    TempDigest =  get_sha_from_key(sha256,Key),
    % Generate Structure for SignedInfo and retur this
    Result = esaml_util:build_nsinfo(Ns, #xmlElement{
        name = 'ds:SignedInfo',
        content = [
            #xmlElement{name = 'ds:CanonicalizationMethod',
                attributes = [#xmlAttribute{name = 'Algorithm', value = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"}]},
            #xmlElement{name = 'ds:SignatureMethod',
                attributes = [#xmlAttribute{name = 'Algorithm', value = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"}]},
            #xmlElement{name = 'ds:Reference',
                attributes = [#xmlAttribute{name = 'URI', value = "#" ++ Id}],
                content = [
                    #xmlElement{name = 'ds:Transforms', content = [
                        #xmlElement{name = 'ds:Transform',
                            attributes = [#xmlAttribute{name = 'Algorithm', value = "http://www.w3.org/TR/1999/REC-xpath-19991116"}],
                            content = [
                                #xmlElement{name = 'ds:XPath',
                                   content=[#xmlText{value="not(ancestor-or-self::*[namespace-uri()=\"http://www.w3.org/2000/09/xmldsig#\" and local-name()=\"Signature\"])"}]}
                                ]}
                        ]},
                    
                    #xmlElement{name = 'ds:DigestMethod',
                        attributes = [#xmlAttribute{name = 'Algorithm', value = DigestMethod}]},
                    #xmlElement{name = 'ds:DigestValue',
                        content = [#xmlText{value = DigestValue}]}
                ]},
             #xmlElement{name = 'ds:Reference',
                attributes = [#xmlAttribute{name = 'URI', value = SignedProperties}],
                content = [
                    #xmlElement{name = 'ds:Transforms', content = [
                        #xmlElement{name = 'ds:Transform',
                            attributes = [#xmlAttribute{name = 'Algorithm', value = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"}]}
                        ]},
                    
                    #xmlElement{name = 'ds:DigestMethod',
                        attributes = [#xmlAttribute{name = 'Algorithm', value = DigestMethod}]},
                    #xmlElement{name = 'ds:DigestValue',
                        content = [#xmlText{value = DigestPrivateKey}]}
                ]}
        ]
    }),
     Result.


generate_xades_sing_element(HashFunction, SigInfoCanon, Ns, Target, CertBinList, SignedProperties) ->
    DigestValueSingInfo = base64:encode_to_string(
       crypto:hash(HashFunction, unicode:characters_to_binary(SigInfoCanon))),
    SubjectCertificate = os:cmd("openssl x509 -noout -in /home/renato/Downloads/desenvolvimento/cpd/git/certificado/certificado_fabiano/publicCert.pem -subject"),
    SerialX509NumberHex = os:cmd("openssl x509 -in /home/renato/Downloads/desenvolvimento/cpd/git/certificado/certificado_fabiano/publicCert.pem -serial -noout"),
    % openssl x509 -noout -subject -in ca.pem
    % openssl x509 -in publicCert.pem -serial -issuer
    % openssl x509 -noout -serial -in publicCert.pem
    ChainCertificate = esaml_util:load_certificate_chain("/home/renato/Downloads/desenvolvimento/cpd/git/certificado/certificado_fabiano/publicCert.pem"),
    Serialx509NumberList = re:split(lists:nth(2,re:split(SerialX509NumberHex, "=")),"\n"),
    SerialX509NumberDecimal = binary_to_integer(lists:nth(1,Serialx509NumberList), 16),
    SerialX509String = lists:flatten(io_lib:format("~p", [SerialX509NumberDecimal])),
    ListCetifiedX509 = add_encapsulated_certificate([],ChainCertificate),
    [_Item1,_] = ListCetifiedX509,
    [_,_Item2] = ListCetifiedX509,
    %Return element xades for signature
     esaml_util:build_nsinfo(Ns, #xmlElement{
        name = 'ds:Object',
        attributes = [#xmlAttribute{name='id', value="xades"}],
        content = [
            #xmlElement{name='xades:QualifyingProperties',
                attributes=[#xmlAttribute{name='xmlns:xades', value="http://uri.etsi.org/01903/v1.3.2#"},
                    #xmlAttribute{name='Target', value= string:concat("#",Target)}],
            content = [
                #xmlElement{name='xades:SignedProperties',
                    attributes= [#xmlAttribute{name='Id', value=SignedProperties}],
                content = [
                    #xmlElement{name='xades:SignedSignatureProperties',
                        content = [
                            #xmlElement{name='xades:SigningTime',
                                content=[#xmlText{value = esaml_util:datetime_to_saml(calendar:local_time())}]},
                            #xmlElement{name='xades:SigningCertificate',
                                content=[
                                        #xmlElement{name='xades:Cert',
                                            content=[
                                                #xmlElement{name='xades:CertDigest',
                                                    content=[
                                                        #xmlElement{name='ds:DigestMethod',
                                                            attributes=[#xmlAttribute{name='Algorithm', value="http://www.w3.org/2001/04/xmlenc#sha256"}]},
                                                        #xmlElement{name='ds:DigestValue',
                                                            content=[#xmlText{value=DigestValueSingInfo}]}
                                                        ]},
                                                #xmlElement{name='xades:IssuerSerial',
                                                    content=[
                                                        #xmlElement{name='ds:X509IssuerName',
                                                            content=[#xmlText{value=SubjectCertificate}]},
                                                        #xmlElement{name='ds:X509SerialNumber',
                                                            content=[#xmlText{value=SerialX509String}]}    
                                                        ]}
                                                ]}

                                    ]},
                            #xmlElement{name='xades:SignaturePolicyIdentifier',
                                content=[
                                #xmlElement{name='xades:SignaturePolicyId',
                                    content=[
                                    #xmlElement{name='xades:SigPolicyId',
                                        content=[
                                        #xmlElement{name='xades:Identifier',
                                            attributes=[#xmlAttribute{name='Qualifier', value="OIDAsURN"}],
                                            content=[#xmlText{value="urn:oid:2.16.76.1.7.1.6.2.3"}]}
                                    ]},      
                                    #xmlElement{name='xades:SigPolicyHash',
                                        content=[
                                        #xmlElement{name='ds:DigestMethod',
                                            attributes=[#xmlAttribute{name='Algorithm', value="http://www.w3.org/2001/04/xmlenc#sha256"}]},
                                        #xmlElement{name='ds:DigestValue',
                                            content=[#xmlText{value="Verify what add in here"}]}    
                                            ]},
                                    #xmlElement{name='xades:SigPolicyQualifiers',
                                        content=[
                                        #xmlElement{name='xades:SigPolicyQualifier',
                                            content=[
                                                #xmlElement{name='xades:SPURI',
                                                    content=[#xmlText{value="http://politicas.icpbrasil.gov.br/PA_AD_RB_v2_3.xml"}]}
                                                ]}    
                                        ]}
                                     ]}

                                ]}

                            ]}
                        
                    ]},
                    #xmlElement{name='xades:UnsignedProperties',
                        content=[
                        #xmlElement{name='xades:UnsignedSignatureProperties',
                            content =[
                                  #xmlElement{name='xades:CertificateValues',
                                  content=[_Item1,_Item2]}    
                            ]}
                        ]}    
                ]}    
        ]
    }).



add_encapsulated_certificate(ElementArray,[]) ->
    ElementArray;
add_encapsulated_certificate(ElementArray,[H|T]) ->
    Cert64 = base64:encode_to_string(H),
    Element = [#xmlElement{name='xades:EncapsulatedX509Certificate',
        content=[#xmlText{value=Cert64}]
    }],
    add_encapsulated_certificate(lists:append(ElementArray, Element),T).


generate_element_ds_signature(SigInfo,SigElemObject, Sig64, Cert64, Ns, Target) ->
      % get all others elements and get in ds:signature
      esaml_util:build_nsinfo(Ns, #xmlElement{
        name = 'ds:Signature',
        attributes = [#xmlAttribute{name = 'xmlns:ds', value = "http://www.w3.org/2000/09/xmldsig#"},
                      #xmlAttribute{name = 'Id', value = Target}],
        content = [
            SigInfo,
            #xmlElement{name = 'ds:SignatureValue', content = [#xmlText{value = Sig64}]},
            #xmlElement{name = 'ds:KeyInfo', content = [
                #xmlElement{name = 'ds:X509Data', content = [
                    #xmlElement{name = 'ds:X509Certificate', content = [#xmlText{value = Cert64} ]}]}]},
            SigElemObject
        ]
    }).


read_private_key(FilePrivateKey) ->
      RawSKey =  ems_util:open_file(FilePrivateKey),
      [EncSKey] = public_key:pem_decode(RawSKey),
      SKey = public_key:pem_entry_decode(EncSKey),   
      SKey.

read_private_key_encoded(FilePrivateKey) ->
      RawSKey =  ems_util:open_file(FilePrivateKey),
      [EncSKey] = public_key:pem_decode(RawSKey),
      EncSKey.
    


read_certificate(FileCertificate) ->
  ContentCert = ems_util:open_file(FileCertificate),
  public_key:pem_decode(ContentCert).

read_file_xml(PathFileXml) ->
    File = ems_util:open_file(PathFileXml),
    binary_to_list(File).

transform_tuple_in_xml(Xml) ->
    Export=xmerl:export_simple([Xml],xmerl_xml),
    lists:flatten(Export).

create_file_signed(NamePathFile, XmlSigned) ->
    file:write_file(NamePathFile, XmlSigned),
    ok.



%% @doc Returns the canonical digest of an (optionally signed) element
%%
%% Strips any XML digital signatures and applies any relevant InclusiveNamespaces
%% before generating the digest.
-spec digest(Element :: #xmlElement{}) -> binary().
digest(Element) -> digest(Element, sha).

-spec digest(Element :: #xmlElement{}, HashFunction :: sha | sha256) -> binary().
digest(Element, HashFunction) ->
    DsNs = [{"ds", 'http://www.w3.org/2000/09/xmldsig#'},
        {"ec", 'http://www.w3.org/2001/10/xml-exc-c14n#'}],
    Txs = xmerl_xpath:string("ds:Signature/ds:SignedInfo/ds:Reference/ds:Transforms/ds:Transform[@Algorithm='http://www.w3.org/2001/10/xml-exc-c14n#']", Element, [{namespace, DsNs}]),
    InclNs = case Txs of
        [C14nTx = #xmlElement{}] ->
            case xmerl_xpath:string("ec:InclusiveNamespaces/@PrefixList", C14nTx, [{namespace, DsNs}]) of
                [] -> 
                    [];
                [#xmlAttribute{value = NsList}] -> 
                    string:tokens(NsList, " ,")
            end;
        _ -> 
            []
    end,

    CanonXml = xmerl_c14n:c14n(Element, false, InclNs),
    CanonXmlUtf8 = unicode:characters_to_binary(CanonXml, unicode, utf8),
    crypto:hash(HashFunction, CanonXmlUtf8).

%% @doc Verifies an XML digital signature on the given element.
%%
%% Fingerprints is a list of valid cert fingerprints that can be
%% accepted.
%%
%% Will throw badmatch errors if you give it XML that is not signed
%% according to the xml-dsig spec. If you're using something other
%% than rsa+sha1 or sha256 this will asplode. Don't say I didn't warn you.
-spec verify(Element :: #xmlElement{}, Fingerprints :: [fingerprint()] | any) -> ok | {error, bad_digest | bad_signature | cert_not_accepted}.
verify(Element, Fingerprints) ->
    DsNs = [{"ds", 'http://www.w3.org/2000/09/xmldsig#'},
        {"ec", 'http://www.w3.org/2001/10/xml-exc-c14n#'}],
    [#xmlAttribute{value = SignatureMethodAlgorithm}] = xmerl_xpath:string("ds:Signature/ds:SignedInfo/ds:SignatureMethod/@Algorithm", Element, [{namespace, DsNs}]),
    {HashFunction, _, _} = signature_props(SignatureMethodAlgorithm),

    [#xmlAttribute{value = "http://www.w3.org/2001/10/xml-exc-c14n#"}] = xmerl_xpath:string("ds:Signature/ds:SignedInfo/ds:CanonicalizationMethod/@Algorithm", Element, [{namespace, DsNs}]),
    [#xmlAttribute{value = SignatureMethodAlgorithm}] = xmerl_xpath:string("ds:Signature/ds:SignedInfo/ds:SignatureMethod/@Algorithm", Element, [{namespace, DsNs}]),
    [C14nTx = #xmlElement{}] = xmerl_xpath:string("ds:Signature/ds:SignedInfo/ds:Reference/ds:Transforms/ds:Transform[@Algorithm='http://www.w3.org/2001/10/xml-exc-c14n#']", Element, [{namespace, DsNs}]),
    InclNs = case xmerl_xpath:string("ec:InclusiveNamespaces/@PrefixList", C14nTx, [{namespace, DsNs}]) of
        [] -> [];
        [#xmlAttribute{value = NsList}] -> string:tokens(NsList, " ,")
    end,

    CanonXml = xmerl_c14n:c14n(strip(Element), false, InclNs),
    CanonXmlUtf8 = unicode:characters_to_binary(CanonXml),
    CanonSha = crypto:hash(HashFunction, CanonXmlUtf8),

    [#xmlText{value = Sha64}] = xmerl_xpath:string("ds:Signature/ds:SignedInfo/ds:Reference/ds:DigestValue/text()", Element, [{namespace, DsNs}]),
    CanonSha2 = base64:decode(Sha64),

    if not (CanonSha =:= CanonSha2) ->
        {error, bad_digest};

    true ->
        [SigInfo] = xmerl_xpath:string("ds:Signature/ds:SignedInfo", Element, [{namespace, DsNs}]),
        SigInfoCanon = xmerl_c14n:c14n(SigInfo),
        Data = list_to_binary(SigInfoCanon),

        [#xmlText{value = Sig64}] = xmerl_xpath:string("ds:Signature//ds:SignatureValue/text()", Element, [{namespace, DsNs}]),
        Sig = base64:decode(Sig64),

        [#xmlText{value = Cert64}] = xmerl_xpath:string("ds:Signature//ds:X509Certificate/text()", Element, [{namespace, DsNs}]),
        CertBin = base64:decode(Cert64),
        CertHash = crypto:hash(sha, CertBin),
        CertHash2 = crypto:hash(sha256, CertBin),

        Cert = public_key:pkix_decode_cert(CertBin, plain),
        {_, KeyBin} = Cert#'Certificate'.tbsCertificate#'TBSCertificate'.subjectPublicKeyInfo#'SubjectPublicKeyInfo'.subjectPublicKey,
        Key = public_key:pem_entry_decode({'RSAPublicKey', KeyBin, not_encrypted}),

        case public_key:verify(Data, HashFunction, Sig, Key) of
            true ->
                case Fingerprints of
                    any ->
                        ok;
                    _ ->
                        case lists:any(fun(X) -> lists:member(X, Fingerprints) end, [CertHash, {sha,CertHash}, {sha256,CertHash2}]) of
                            true ->
                                ok;
                            false ->
                                {error, cert_not_accepted}
                        end
                end;
            false ->
                {error, bad_signature}
        end
    end.

%% @doc Verifies an XML digital signature, trusting any valid certificate.
%%
%% This is really not recommended for production use, but it's handy in
%% testing/development.
-spec verify(Element :: xml_thing()) -> ok | {error, bad_digest | bad_signature | cert_not_accepted}.
verify(Element) ->
    verify(Element, any).

-spec signature_props(atom() | string()) -> {HashFunction :: atom(), DigestMethodUrl :: string(), SignatureMethodUrl :: string()}.
signature_props("http://www.w3.org/2000/09/xmldsig#rsa-sha1") ->
    signature_props(rsa_sha1);
signature_props(rsa_sha1) ->
    HashFunction = sha,
    DigestMethod = "http://www.w3.org/2000/09/xmldsig#sha1",
    Url = "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
    {HashFunction, DigestMethod, Url};
signature_props("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256") ->
    signature_props(rsa_sha256);
signature_props(rsa_sha256) ->
    HashFunction = sha256,
    DigestMethod = "http://www.w3.org/2001/04/xmlenc#sha256",
    Url = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
    {HashFunction, DigestMethod, Url}.

get_sha_from_key(ShaMethod,Key) ->
  crypto:hash(ShaMethod,Key).
