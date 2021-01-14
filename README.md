## Diagram
[![Foo](https://i0.wp.com/piotrminkowski.com/wp-content/uploads/2020/10/spring-cloud-gateway-oauth2-login.png?resize=700%2C335&ssl=1)](https://piotrminkowski.com/2020/10/09/spring-cloud-gateway-oauth2-with-keycloak/)  

First, let’s take a look at the picture that illustrates our use case. We are calling POST /login endpoint on the gateway (1).

After receiving the login request Spring Cloud Gateway try to obtain the access token from the authorization server (2). 

Then Keycloak is returning the JWT access token. As a result, Spring Cloud Gateway is calling the userinfo endpoint (3). 

After receiving the response it is creating a web session and Authentication bean. Finally, the gateway application is returning a session id to the external client (4). 

The external client is using a cookie with session-id to authorize requests. It calls GET ping from the callme application (5). 

The gateway application is forwarding the request to the downstream service (6). 

However, it removes the cookie and replaces it with a JWT access token. The callme application verifies an incoming token (7). 

Finally, it returns 200 OK response if the client is allowed to call endpoint (8). Otherwise, it returns 403

## Keycloak
Let Keycloak to use port 8888 ,we adjust startup's script.

```powershell
## windows
keycloak-[version]\bin\standalone.bat  -Djboss.socket.binding.port-offset=808
## linux
keycloak-[version]/bin>$ standalone.sh  -Djboss.socket.binding.port-offset=808
```
Then we need to create two clients with the same names as defined inside the gateway configuration. Both of them need to have ***confidential*** in the “Access Type” section, a valid redirection URI set. We may use a simple wildcard while setting the redirection address as shown below.  
[![Foo](https://i1.wp.com/piotrminkowski.com/wp-content/uploads/2020/10/spring-cloud-gateway-oauth2-client.jpg?resize=700%2C518&ssl=1)](https://piotrminkowski.com/2020/10/09/spring-cloud-gateway-oauth2-with-keycloak/)    
The client ***spring-with-test-scope*** will have the scope ***TEST*** assigned. In contrast, the second client ***spring-without-test-scope*** will not have the scope ***TEST*** assigned.
[![Foo](https://i0.wp.com/piotrminkowski.com/wp-content/uploads/2020/10/spring-cloud-gateway-oauth2-clientscope.jpg?resize=700%2C207&ssl=1)](https://piotrminkowski.com/2020/10/09/spring-cloud-gateway-oauth2-with-keycloak/)  
### Step 1. Adjust Gateway's Configuration

We have to adjust the configuration of the gateway which calling Keycloak .  To adjsut ***spring.security.oauth2.provider*** and  ***spring.security.oauth2.registration***.

```yaml
spring:
  application:
    name: gateway
  cloud:
    gateway:
      default-filters:
        - TokenRelay
      routes:
        - id: callme-service
          uri: http://127.0.0.1:8040
          predicates:
            - Path=/callme/**
          filters:
            - RemoveRequestHeader=Cookie
  security:
    oauth2:
      client:
        provider:
          keycloak:
            token-uri: http://localhost:8888/auth/realms/master/protocol/openid-connect/token
            authorization-uri: http://localhost:8888/auth/realms/master/protocol/openid-connect/auth
            userinfo-uri: http://localhost:8888/auth/realms/master/protocol/openid-connect/userinfo
            user-name-attribute: preferred_username
        registration:
          keycloak-with-test-scope:
            provider: keycloak
            client-id: spring-with-test-scope
            client-secret: 31584801-158a-4c5c-ae8a-b24b72e9fcff
            authorization-grant-type: authorization_code
            redirect-uri: "{baseUrl}/login/oauth2/code/keycloak"
          keycloak-without-test-scope:
            provider: keycloak
            client-id: spring-without-test-scope
            client-secret: f6fc369d-49ce-4132-8282-5b5d413eba23
            authorization-grant-type: authorization_code
            redirect-uri: "{baseUrl}/login/oauth2/code/keycloak"

server.port: 8060

logging.level:
  org.springframework.cloud.gateway: DEBUG
  org.springframework.security: DEBUG
  org.springframework.web.reactive.function.client: TRACE
```

### Step 2. Adjust Resource Server's Configuration  
 To adjsut ***spring.security.oauth2.resourceserver.jwt.issuer-uri*** .

```yaml
spring:
  application:
    name: callme
  security:
    oauth2:
      resourceserver:
        jwt:
          issuer-uri: http://localhost:8888/auth/realms/master

logging.level:
  org.springframework.cloud.gateway: DEBUG
  org.springframework.security: DEBUG
  org.springframework.web.reactive.function.client: TRACE

server.port: 8040
```

## About Authorization
to see the CallmeController.java in callme.  
```java
package pl.piomin.samples.security.callme.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/callme")
public class CallmeController {

	@PreAuthorize("hasAuthority('SCOPE_TEST')")
	@GetMapping("/ping")
	public String ping() {
		SecurityContext context = SecurityContextHolder.getContext();
		Authentication authentication = context.getAuthentication();
		return "Scopes: " + authentication.getAuthorities();
	}
}

```

You can test Client Scopes' effect.