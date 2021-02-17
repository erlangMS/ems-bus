#!/usr/bin/php
#
# Title: ERLANGMS ldap client tool (php version)
# Author: Everton de Vargas Agilar <evertonagilar@gmail.com>
#         Jonatas Santiago         <jonatasantiago@unb.br>	
# Data: 13/01/2016
#
# Modo de uso: $ ./ldap_client.sh server user. Ex.: ./ldap_client servicosssi.unb.br geral 
#     server => IP ou domain name do servidor  (default localhost)
#     user => usuário de pesquisa
#
# Requisitos: PHP e ldap-php habilitado
#

<?php
set_time_limit(30);
error_reporting(E_ALL);
ini_set('error_reporting', E_ALL);
ini_set('display_errors',1);

// Verifica parâmetros de linha de comando
if($argc == 3){
	// 3 parâmetros = executavel + server + user
	$ldapserver 	= $argv[1];
	$ldapuser   	= $argv[2];  
}else if($argc == 2){
	// 2 parâmetros = executavel + user
	$ldapserver 	= 'localhost';
	$ldapuser   	= $argv[1];  
}else{
	die ('Modo de uso: ./ldap_client.php server user. Ex.: ./ldap_client.php servicosssi.unb.br geral');
}


$ldapport		= 2389;
$ldappass   	= "123456";					 // senha do admin do ldap
$ldap_basedn   	= "dc=unb,dc=br";			 // é o parâmetro -b do comando ldapsearch
$ldaprdn 	 	= "cn=admin,dc=unb,dc=br";   // é o parâmetro -D do comando ldapsearch 
$ldap_filter 	= "uid=$ldapuser";		     // o filtro esperado pelo barramento

echo "Pesquisando dados do usuário $ldapuser no servidor $ldapserver:$ldapport\n";

// connect 
$ldapconn = ldap_connect($ldapserver, $ldapport) or die("Could not connect to LDAP server.");

if($ldapconn) {
	ldap_set_option($ldapconn, LDAP_OPT_PROTOCOL_VERSION, 3);
	ldap_set_option($ldapconn, LDAP_OPT_REFERRALS, 0);

    // binding to ldap server
    $ldapbind = ldap_bind($ldapconn, $ldaprdn, $ldappass) or die ("Error trying to bind: ".ldap_error($ldapconn));

    // verify binding
    if ($ldapbind) {
        
        $result = ldap_search($ldapconn, $ldap_basedn, $ldap_filter) or die ("Error in search query: ".ldap_error($ldapconn));
        $data = ldap_get_entries($ldapconn, $result);
        
        // SHOW ALL DATA
        echo "";
        print_r($data);    
       
        
    } else {
        echo "LDAP bind failed...";
    }

}

// all done? clean up
ldap_close($ldapconn);
?>

