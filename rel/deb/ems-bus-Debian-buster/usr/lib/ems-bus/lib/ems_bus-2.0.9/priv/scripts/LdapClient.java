/*********************************************************************
 * @title "ERLANGMS ldap client tool
 * @version 1.0.0
 * @doc Utility to query users on the ems-bus
 * @author  Everton de Vargas Agilar <evertonagilar@gmail.com>
 * 			Renato Carauta			 <rcarauta@unb.br> 
 * @copyright ErlangMS Team
 *********************************************************************/
 
import java.util.Hashtable;
import javax.naming.*;
import javax.naming.directory.*;
import javax.naming.ldap.InitialLdapContext;
import javax.naming.ldap.LdapContext;
import java.io.BufferedReader;
import java.io.Console;
import java.io.IOException;
import java.io.InputStreamReader;

public class LdapClient {

	// declared in EmsUtil
	public static Object ldapSearch(final String login, final String adminPasswd, String urlLdapServer) {
		Hashtable<String, String> env = new Hashtable<String, String>(11);
		env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
		env.put(Context.PROVIDER_URL, urlLdapServer);  
		env.put(Context.SECURITY_AUTHENTICATION, "simple");
		env.put(Context.SECURITY_PRINCIPAL, "cn=admin,dc=unb,dc=br");
		env.put(Context.SECURITY_CREDENTIALS, adminPasswd);  // Admin password in ems_ldap_server.json catalog
		LdapContext ctx = null;
		try{
			ctx = new InitialLdapContext(env, null);
			try{
				NamingEnumeration<SearchResult> answer = ctx.search("dc=unb,dc=br", "uid="+ login, null);
				while (answer.hasMore()){
					SearchResult result = answer.next();
					System.out.println(result.getAttributes());
				}
			    return answer; 
			}finally{
				ctx.close();
			}
		} catch (javax.naming.AuthenticationException e) {
			System.out.println("Invalid admin credentials.");
			return null;
		} catch (NamingException e){
			System.out.println("Could not connect to ldap server.");
			return null;
		}
	}

	public static void help(){
		System.out.println("ERLANGMS ldap client tool (Java version v1.0)");
		System.out.println("Modo de usar 1: java ldap_client host_ldap login admin_passwd");
		System.out.println("Modo de usar 2: java ldap_client login admin_passwd");
		System.out.println("Modo de usar 3: java ldap_client loginr");
		System.out.println("default host_ldap is localhost:2389");
		System.out.println("admin_passwd is not the user's password");
	}
	
	public static void main(String[] args) {
		String url = "ldap://localhost:2389";
		String login = null;
		String adminPasswd = null;
		
		// check parameters
		if (args.length == 3){
			url = args[0];  
			login = args[1];
			adminPasswd = args[2];
		} else if (args.length == 2){
			login = args[0];
			adminPasswd = args[1];
		} else if (args.length == 1){
			if (args[0].equals("--help") || args[0].equals("-help")){
				help();
				return;
			}else{
				login = args[0];
				Console console = System.console();
				console.printf("Enter the ldap admin password for authentication: ");
				char[] passwordChars = console.readPassword();
				adminPasswd = new String(passwordChars);
			}
		}else{
			help();
			return;
		}

		if (url.isEmpty()){
			System.out.println("Server Url ldap not informed!");
			return;
		}

		if (login.isEmpty()){
			System.out.println("User login for search not informed!");
			return;
		}
		
		// add port if necessary
		if (url.indexOf(":") == -1){
			url = url + ":2389";
		}

		// add ldap:// if necessary
		if (!url.startsWith("ldap://")){
			url = "ldap://" + url;
		}

		System.out.println("Ldap search login "+ login + " on " + url + ":");
		ldapSearch(login, adminPasswd, url);
	}
	
}
