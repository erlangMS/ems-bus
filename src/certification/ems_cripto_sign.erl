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

-export([execute/1,verify/1, verify/2, sign/4, strip/1, digest/1, sign_256_key/0]).

-include_lib("xmerl/include/xmerl.hrl").
-include_lib("public_key/include/public_key.hrl").
-include("../include/ems_schema.hrl").

-type xml_thing() :: #xmlDocument{} | #xmlElement{} | #xmlAttribute{} | #xmlPI{} | #xmlText{} | #xmlComment{}.
-type sig_method() :: rsa_sha1 | rsa_sha256.
-type sig_method_uri() :: string().
-type fingerprint() :: binary() | {sha | sha256, binary()}.

execute(Request) -> 

    {Docs, _} = xmerl_scan:string("<?xml version=\"1.0\" encoding=\"UTF-8\"?><Diploma><content>Content of the certificate...</content></Diploma>", [{namespace_conformant, true}]),
    %{Key, CertBin} = sign_256_key(),
    Key = read_private_key("/home/renato/Downloads/desenvolvimento/cpd/git/barramento/certificado/certificado/certificado_fabiano/private_key.pem"),
    CertBin = read_certificate("/home/renato/Downloads/desenvolvimento/cpd/git/barramento/certificado/certificado/certificado_fabiano/publicCert.pem"),
    SignedXml = sign(Docs, Key, rsa_sha256, CertBin),
    XmlFormater = transform_tuple_in_xml(SignedXml),
    create_file_signed("/home/renato/Downloads/desenvolvimento/cpd/git/barramento/certificado/certificado/test_signed/signed_xml.xml",XmlFormater),
    %Doc = strip(SignedXml), 
    %ok = verify(SignedXml, [crypto:hash(sha, CertBin)]),
    {ok, Request#request{code = 200,
            content_type_out = <<"application/json">>,
            response_data = <<"{\"response\" : \" Work correctlly!\"}">>}
	}.

sign_256_key() ->
    CertBin = <<48,130,2,88,48,130,1,193,160,3,2,1,2,2,9,0,143,6,244,72,167,203,103,249,48,
                     13,6,9,42,134,72,134,247,13,1,1,11,5,0,48,69,49,11,48,9,6,3,85,4,6,19,2,65,
                     85,49,19,48,17,6,3,85,4,8,12,10,83,111,109,101,45,83,116,97,116,101,49,33,48,
                     31,6,3,85,4,10,12,24,73,110,116,101,114,110,101,116,32,87,105,100,103,105,
                     116,115,32,80,116,121,32,76,116,100,48,30,23,13,49,53,48,49,48,57,48,53,53,
                     56,50,56,90,23,13,49,56,48,49,48,56,48,53,53,56,50,56,90,48,69,49,11,48,9,6,
                     3,85,4,6,19,2,65,85,49,19,48,17,6,3,85,4,8,12,10,83,111,109,101,45,83,116,97,
                     116,101,49,33,48,31,6,3,85,4,10,12,24,73,110,116,101,114,110,101,116,32,87,
                     105,100,103,105,116,115,32,80,116,121,32,76,116,100,48,129,159,48,13,6,9,42,
                     134,72,134,247,13,1,1,1,5,0,3,129,141,0,48,129,137,2,129,129,0,226,96,97,235,
                     98,1,16,138,195,252,131,198,89,74,61,140,212,78,159,123,99,28,153,153,53,193,
                     67,109,72,5,148,219,215,43,114,158,115,146,245,138,110,187,86,167,232,15,75,
                     90,39,50,192,75,180,64,97,107,84,135,124,189,87,96,62,133,63,147,146,200,97,
                     209,193,17,186,23,41,243,247,94,51,116,64,104,108,253,157,152,31,189,28,67,
                     24,20,12,216,67,144,186,216,245,111,142,219,106,11,59,106,147,184,89,104,55,
                     80,79,112,40,181,99,211,254,130,151,2,109,137,153,40,216,255,2,3,1,0,1,163,
                     80,48,78,48,29,6,3,85,29,14,4,22,4,20,226,28,15,2,132,199,176,227,86,54,191,
                     35,102,122,246,50,138,160,135,239,48,31,6,3,85,29,35,4,24,48,22,128,20,226,
                     28,15,2,132,199,176,227,86,54,191,35,102,122,246,50,138,160,135,239,48,12,6,
                     3,85,29,19,4,5,48,3,1,1,255,48,13,6,9,42,134,72,134,247,13,1,1,11,5,0,3,129,
                     129,0,205,96,78,143,187,166,157,119,160,185,177,84,220,232,121,254,52,50,111,
                     54,114,42,132,147,98,202,12,7,194,120,234,67,26,218,126,193,245,72,75,95,224,
                     211,23,244,240,57,207,46,99,142,76,218,100,184,132,172,34,73,193,145,142,72,
                     53,165,23,144,255,102,86,99,42,254,82,107,53,119,240,62,200,212,83,220,57,80,
                     230,146,109,43,211,31,166,82,178,55,114,110,148,164,247,254,162,135,126,157,
                     123,185,30,146,185,60,125,234,98,188,205,109,134,74,58,230,84,245,87,233,232,
                     133,5,2>>,
    Key = {'RSAPrivateKey', 'two-prime',
                                    158966980232852666772927195913239826068125056530979279609712979168793279569950881734703825673400914686519075266453462906345312980842795804140929898282998881309114359443174166979208804324900933216050217378336424610098894747923637370129796798783736195833452722831496313972485597624172644388752444143966442019071,
                                    65537,
                                    81585278241787073666896657377387148477980168094656271566789692148593343582026914676392925775132211811359523575799353416465883426318681613016771856031686932947271317419547861320644294073546214321361245588222429356422579589512434099189282561422126611592192445638395200306602306031474495398876927483244443369593,
                                    12815152123986810526369994227491082588178787406540561310765978351462418958697931052574961306076834858513248417634296430722377133684866082077619514584491459,
                                    12404611251965211323458298415076779598256259333742031592133644354834252221601927657224330177651511823990769238743820731690160529549534378492093966021787669,
                                    12713470949925240093275522448216850277486308815036508762104942467263257296453352812079684136246663289377845680597663167924634849028624106358859697266275251,
                                    6810924077860081545742457087875899675964008664805732102649450821129373208143854079642954317600927742717607462760847234526126256852014054284747688684682049,
                                    4159324767638175662417764641421395971040638684938277905991804960733387537828956767796004537366153684030130407445292440219293856342103196426697248208199489,
                                    asn1_NOVALUE},
    {Key, CertBin}.


%% @doc Returns an xmlelement without any ds:Signature elements that are inside it.
-spec strip(Element :: #xmlElement{} | #xmlDocument{}) -> #xmlElement{}.
strip(#xmlDocument{content = Kids} = Doc) ->
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
sign(ElementIn, PrivateKey, SigMethod, [])  ->
    io:format("Aqui Errado >>>>>>>>>>>>>>>>>>>>>>>>> ~n~n"),
    ElementIn;
sign(ElementIn, PrivateKey, SigMethod, [H|T]) ->
    io:format("H >>>>>>>>>>>>>>>>>>>>>>>>>>>> ~p~n~n",[H]),
    io:format("T >>>>>>>>>>>>>>>>>>>>>>>>>>>> ~p~n~n",[T]),
    % Transforma o documento Xml em uma lista chave e valor
    io:format("Aqui 1 >>>>>>>>>>>>>>>>>>>>>>>>>>>>> ~n~n"),
    io:format("Elem >>>>>>>>>>>>>>>>>>>>>>>>>>> ~p~n~n",[ElementIn]),
    CertBin = element(2,H),
    %ElementStrip = strip(ElementIn),
    % make sure the root element has an ID... if it doesn't yet, add one
    io:format("Aqui 2 >>>>>>>>>>>>>>>>>>>>>>>>>>>> ~n~n"),
    {Element, Id} = case lists:keyfind('ID', 2, ElementIn#xmlElement.attributes) of
        #xmlAttribute{value = CapId} ->
            io:format("Aqui 3 >>>>>>>>>>>>>>>>>>>>>>>>>>>> ~n~n"),
            {ElementIn, CapId};
        _ ->
            case lists:keyfind('id', 2, ElementIn#xmlElement.attributes) of
                #xmlAttribute{value = LowId} ->
                    io:format("Aqui 4 >>>>>>>>>>>>>>>>>>>>>>>>>>>> ~n~n"),
                    {ElementIn, LowId};
                _ ->
                    io:format("Aqui 5 >>>>>>>>>>>>>>>>>>>>>>>>>>>> ~n~n"),
                    NewId = uuid:to_string(uuid:uuid4()),
                    io:format("Aqui 6 >>>>>>>>>>>>>>>>>>>>>>>>>>>> ~n~n"),
                    Attr = #xmlAttribute{name = 'ID', value = NewId, namespace = #xmlNamespace{}},
                    io:format("Aqui 7 >>>>>>>>>>>>>>>>>>>>>>>>>>>> ~n~n"),
                    NewAttrs = [Attr | ElementIn#xmlElement.attributes],
                    Elem = ElementIn#xmlElement{attributes = NewAttrs},
                    {Elem, NewId}
            end
    end,

    % start create de signature elements in xades pattern
    {HashFunction, DigestMethod, SignatureMethodAlgorithm} = signature_props(SigMethod),
    % create a ds with url signature
    Ns = #xmlNamespace{nodes = [{"ds", 'http://www.w3.org/2000/09/xmldsig#'}]},
    % first we need the digest, to generate our SignedInfo element
    SigInfo = generate_sing_info_element(Element, HashFunction, SignatureMethodAlgorithm, DigestMethod, Ns, Id),
    SigInfoCanon = xmerl_c14n:c14n(SigInfo),
    SigElemObject =  generate_xades_sing_element(HashFunction, SigInfoCanon, Ns),
    % now we sign the SignedInfo element...  
    Data = unicode:characters_to_binary(SigInfoCanon, unicode, utf8),
    Signature = public_key:sign(Data, HashFunction, PrivateKey),
    %change bin sign in base 64 sign
    Sig64 = base64:encode_to_string(Signature),
    Cert64 = base64:encode_to_string(CertBin),
    % and wrap it all up with the signature and certificate
    SigElem = generate_element_ds_signature(SigInfo,SigElemObject, Sig64, Cert64, Ns),
    ElementSigned = Element#xmlElement{content = [SigElem | Element#xmlElement.content]},
    sign(ElementSigned, PrivateKey, SigMethod, T).



generate_sing_info_element(Element, HashFunction, SignatureMethodAlgorithm, DigestMethod, Ns, Id) ->
    CanonXml = xmerl_c14n:c14n(Element),
    % create a digest value. 
    DigestValue = base64:encode_to_string(crypto:hash(HashFunction, unicode:characters_to_binary(CanonXml, unicode, utf8))),
    %Generate Structure for SignedInfo and retur this
    esaml_util:build_nsinfo(Ns, #xmlElement{
        name = 'ds:SignedInfo',
        content = [
            #xmlElement{name = 'ds:CanonicalizationMethod',
                attributes = [#xmlAttribute{name = 'Algorithm', value = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments"}]},
            #xmlElement{name = 'ds:SignatureMethod',
                attributes = [#xmlAttribute{name = 'Algorithm', value = SignatureMethodAlgorithm}]},
            #xmlElement{name = 'ds:Reference',
                attributes = [#xmlAttribute{name = 'URI', value = lists:flatten(["#" | Id])}],
                content = [
                    #xmlElement{name = 'ds:Transforms', content = [
                        #xmlElement{name = 'ds:Transform',
                            attributes = [#xmlAttribute{name = 'Algorithm', value = "http://www.w3.org/2000/09/xmldsig#enveloped-signature"}]},
                        #xmlElement{name = 'ds:Transform',
                            attributes = [#xmlAttribute{name = 'Algorithm', value = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments"}]}]},
                    #xmlElement{name = 'ds:DigestMethod',
                        attributes = [#xmlAttribute{name = 'Algorithm', value = DigestMethod}]},
                    #xmlElement{name = 'ds:DigestValue',
                        content = [#xmlText{value = DigestValue}]}
                ]}
        ]
    }).


generate_xades_sing_element(HashFunction, SigInfoCanon, Ns) ->
    io:format("generate_xades_sing_element 1 >>>>>>>>>>>>>>>>>>>>>>>>> ~n~n"),
    DigestValueSingInfo = base64:encode_to_string(
       crypto:hash(HashFunction, unicode:characters_to_binary(SigInfoCanon, unicode, utf8))),

    io:format("generate_xades_sing_element 2 >>>>>>>>>>>>>>>>>>>>>>>>> ~n~n"),
    SubjectCertificate = os:cmd("openssl x509 -noout -in /home/renato/Downloads/desenvolvimento/cpd/git/barramento/certificado/certificado/certificado_fabiano/publicCert.pem -subject"),
    io:format("generate_xades_sing_element 3 >>>>>>>>>>>>>>>>>>>>>>>>> ~n~n"),
    SerialX509NumberHex = os:cmd("openssl x509 -in /home/renato/Downloads/desenvolvimento/cpd/git/barramento/certificado/certificado/certificado_fabiano/publicCert.pem -serial -noout"),
    io:format("generate_xades_sing_element 4 >>>>>>>>>>>>>>>>>>>>>>>>> ~p~n~n",[SerialX509NumberHex]),
    Serialx509NumberList = re:split(lists:nth(2,re:split(SerialX509NumberHex, "=")),"\n"),
    io:format("generate_xades_sing_element 5 >>>>>>>>>>>>>>>>>>>>>>>>> ~n~n"),
    SerialX509NumberDecimal = binary_to_integer(lists:nth(1,Serialx509NumberList), 16),
    io:format("generate_xades_sing_element 6 >>>>>>>>>>>>>>>>>>>>>>>>> ~n~n"),
    SerialX509String = lists:flatten(io_lib:format("~p", [SerialX509NumberDecimal])),
    io:format("generate_xades_sing_element 7 >>>>>>>>>>>>>>>>>>>>>>>>> ~n~n"),
    %Return element xades for signature
    io:format("generate_xades_sing_element 8 >>>>>>>>>>>>>>>>>>>>>>>>> ~n~n"),
     esaml_util:build_nsinfo(Ns, #xmlElement{
        name = 'ds:Object',
        attributes = [#xmlAttribute{name='id', value="xades"}],
        content = [
            #xmlElement{name = 'xades:QualifyingProperties',
                        attributes = [#xmlAttribute{name = 'xmlns:xades', value = "http://uri.etsi.org/01903/v1.3.2#"}],
                        content = [
                            #xmlElement{name = 'xades:SignedProperties',
                            attributes = [#xmlAttribute{name = 'Id', value = "SIG_PROPERTIES_4875"}],
                            content = [
                                #xmlElement{name = 'xades:SigningTime',
                                content = [#xmlText{value = esaml_util:datetime_to_saml(calendar:local_time())}]}
                            ]},
                            #xmlElement{name = 'xades:SigningCertificate',
                            content = [
                                #xmlElement{name = 'xades:Cert',
                                content = [
                                    #xmlElement{name = 'xades:CertDigest',
                                    content = [
                                        #xmlElement{name = 'ds:DigestMethod',
                                        attributes = [#xmlAttribute{name = 'Algorithm', value = "http://www.w3.org/2001/04/xmlenc#sha256"}]},
                                        #xmlElement{name = 'ds:DigestValue',
                                        content = [#xmlText{value = DigestValueSingInfo}]}
                                    ]},
                                #xmlElement{name = 'xades:IssuerSerial',
                                content = [
                                    #xmlElement{name = 'ds:X509IssuerName',
                                    content=[#xmlText{value = SubjectCertificate}]},
                                    #xmlElement{name = 'ds:X509SerialNumber',
                                    content=[#xmlText{value = SerialX509String}]}
                                ]}]}
                            ]},
                          #xmlElement{name = 'xades:SignaturePolicyIdentifier',
                          content = [
                              #xmlElement{name = 'xades:SignaturePolicyId',
                              content = [
                                  #xmlElement{name = 'xades:SigPolicyId',
                                  content = [
                                      #xmlElement{name = 'xades:Identifier',
                                      attributes = [#xmlAttribute{name = 'Qualifier', value = "OIDAsURN"}],
                                      content = [#xmlText{value = "http://uri.etsi.org/01903/v1.2.2#ProofOfOrigin"}]}
                                  ]},
                                  #xmlElement{name = 'xades:SigPolicyHash',
                                  content = [
                                      #xmlElement{name = 'ds:DigestMethod',
                                      attributes = [#xmlAttribute{name = 'Algorithm', value="http://www.w3.org/2001/04/xmlenc#sha256"}]},
                                      #xmlElement{name = 'ds:DigestValue',
                                      content=[#xmlText{value = "Verify what is use in this place"}]}
                                  ]},
                                  #xmlElement{name = 'xades:SigPolicyQualifiers',
                                  content = [
                                      #xmlElement{name = 'xades:SigPolicyQualifier',
                                      content = [
                                          #xmlElement{name = 'xades:SPURI',
                                          content = [#xmlText{value="http://politicas.icpbrasil.gov.br/PA_AD_RB_v2_3.xml"}]}
                                      ]}
                                  ]}
                              ]}
                          ]}
                        ]}
        ]
    }).


generate_element_ds_signature(SigInfo,SigElemObject, Sig64, Cert64, Ns) ->

      % get all others elements and get in ds:signature
      esaml_util:build_nsinfo(Ns, #xmlElement{
        name = 'ds:Signature',
        attributes = [#xmlAttribute{name = 'xmlns:ds', value = "http://www.w3.org/2000/09/xmldsig#"}],
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

read_certificate(FileCertificate) ->
    ContentCert = ems_util:open_file(FileCertificate),
     public_key:pem_decode(ContentCert).


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
                [] -> [];
                [#xmlAttribute{value = NsList}] -> string:tokens(NsList, " ,")
            end;
        _ -> []
    end,

    CanonXml = xmerl_c14n:c14n(strip(Element), false, InclNs),
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
    io:format("Verify Here 1 >>>>>>>>>>>>>>>>>>>>>>> ~n~n"),
    [#xmlAttribute{value = SignatureMethodAlgorithm}] = xmerl_xpath:string("ds:Signature/ds:SignedInfo/ds:SignatureMethod/@Algorithm", Element, [{namespace, DsNs}]),
    io:format("Verify Here 2 >>>>>>>>>>>>>>>>>>>>>>> ~n~n"),
    {HashFunction, _, _} = signature_props(SignatureMethodAlgorithm),
     io:format("Verify Here 3 >>>>>>>>>>>>>>>>>>>>>>> ~n~n"),

    [#xmlAttribute{value = "http://www.w3.org/2001/10/xml-exc-c14n#"}] = xmerl_xpath:string("ds:Signature/ds:SignedInfo/ds:CanonicalizationMethod/@Algorithm", Element, [{namespace, DsNs}]),
     io:format("Verify Here 4 >>>>>>>>>>>>>>>>>>>>>>> ~n~n"),
    [#xmlAttribute{value = SignatureMethodAlgorithm}] = xmerl_xpath:string("ds:Signature/ds:SignedInfo/ds:SignatureMethod/@Algorithm", Element, [{namespace, DsNs}]),
     io:format("Verify Here 5 >>>>>>>>>>>>>>>>>>>>>>> ~n~n"),
    [C14nTx = #xmlElement{}] = xmerl_xpath:string("ds:Signature/ds:SignedInfo/ds:Reference/ds:Transforms/ds:Transform[@Algorithm='http://www.w3.org/2001/10/xml-exc-c14n#']", Element, [{namespace, DsNs}]),
     io:format("Verify Here 6 >>>>>>>>>>>>>>>>>>>>>>> ~n~n"),
    InclNs = case xmerl_xpath:string("ec:InclusiveNamespaces/@PrefixList", C14nTx, [{namespace, DsNs}]) of
        [] -> [];
        [#xmlAttribute{value = NsList}] -> string:tokens(NsList, " ,")
    end,

    CanonXml = xmerl_c14n:c14n(strip(Element), false, InclNs),
    CanonXmlUtf8 = unicode:characters_to_binary(CanonXml, unicode, utf8),
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
