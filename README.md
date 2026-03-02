# ErlangMS

ErlangMS is a Enterprise Service Bus (ESB) developed in *Erlang/OTP* to facilitate the integration of systems through a service-oriented approach for the systems of the University of Brazilia. This work is the result of efforts made in the Master of Applied Computing at the University of Brasilia by graduate student *Everton Vargas Agilar*. 

The ESB consists of a server called *ems-bus* and a *documented architecture* to implement the services in Erlang, Java and future in .NET Framework languages.

## Main design features

* Back-end modular and based on the concept of service catalogs;

* Communication services is through asynchronous messages and requests for services by customers through HTTP/REST or LDAP;

* Published services are specified in a service catalogs in JSON format;

* Published services can be implemented in Erlang or Java;

* Support HTTP Basic authentication;
 
* Support Lightweight Directory Access Protocol (LDAP v3) authentication (Proxy LDAP);

* Support OAuth2 authentication;

* Users, clients, and access profiles to authentication are stored externally to the bus to simplify integration with the enterprise system or SGBD used by the organization.


## Implementing a Hello World service in Erlang or Java language

To implement a new service, you must clone the project in github and save the services implemented in the src folder.

###### 1) First, you must specify the service contract

Open your text editor, enter the following specification and save it to a file called priv/catalog/samples/hello_world.json

```console
[
	{
		"name" : "/samples/hello_world",
		"comment": "Hello World em Erlang",
		"owner": "samples",
		"version": "1",
		"service" : "helloworld_service:execute",
		"url": "/samples/hello_world",
		"type": "GET",
		"authorization" : "public",
		"lang" : "erlang"
	},

	{
		"name" : "/samples/hello_world_java",
		"comment": "Hello World em Java",
		"owner": "samples",
		"version": "1",
		"service" : "br.erlangms.samples.service.HelloWorldService:helloWorld",
		"url": "/samples/hello_world_java",
		"type": "GET",
		"authorization" : "public",
		"lang" : "java"
	}
]
```

###### 2) After, tell the bus about the new service, including an entry in the file priv/catalog/catalog.json

```console
[

	{
		"catalog": "emsbus", 
		"file": "emsbus/ems_main.json"
	},

	{
		"catalog": "hello_world", 
		"file": "samples/hello_world.json"
	}

]
```
Obs.: The priv/catalog/catalog.json file is called the service master catalog and is the first catalog read by the bus during its execution. In this file, there are only includes for other service catalog files.

###### 3) Now, code the service and save in src/samples

```console

-module(helloworld_service).

-include("../include/ems_schema.hrl").

-export([execute/1]).
 
execute(Request) -> 
	{ok, Request#request{code = 200, 
		response_data = <<"{\"message\": \"Hello World!!!\"}">>}
	}.
	
```

During the execution of a service by a client, the bus finds the required service contract and executes the corresponding service code. The Request object is passed to the service code and after it is finished, the result is sent to the client according to the protocol used (HTTP, LDAP, etc).

###### 4) Compile the project and restart the bus

If the service is written in Erlang, you must compile the bus project with the build.sh utility. Later to run ErlangMS in the foreground, use the start.sh utility.

```console
./build.sh
./start.sh
```


###### 5) Now, code the service in Java version

The coded version of the Java service has a design similar to the Erlang version. The service code will receive a Request object and must return the result to the bus. The developer does not have to worry about data serialization since everything is done automatically through the ems_java package provided in the ErlangMS site in github.

```java
package br.erlangms.samples.service;

import javax.ejb.Singleton;
import javax.ejb.Startup;
import br.erlangms.EmsServiceFacade;
import br.erlangms.IEmsRequest;

@Singleton
@Startup
public class HelloWorldFacade extends EmsServiceFacade {

	 public String helloWorld(IEmsRequest request) {
		    return "Hello World!!!";
	 }

}

```



