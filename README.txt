[![Build Status](https://app.travis-ci.com/mtumilowicz/java-spring-boot-oauth2-oidc-pkce-workshop.svg&branch=main)](https://app.travis-ci.com/mtumilowicz/java-spring-boot-oauth2-oidc-pkce-workshop)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)

* references
    * https://www.debugbear.com/basic-auth-header-generator
    * https://github.com/spring-projects/spring-authorization-server/issues/141
    * https://www.baeldung.com/spring-security-pkce-secret-clients
    * https://github.com/eugenp/tutorials/blob/master/spring-security-modules/spring-security-pkce
    * https://www.oauth.com/playground/authorization-code-with-pkce.html
    * https://docs.github.com/en/free-pro-team@latest/developers/apps/creating-an-oauth-app
    * https://rieckpil.de/test-spring-webclient-with-mockwebserver-from-okhttp/
    * https://www.manning.com/books/spring-security-in-action
    * https://stackoverflow.com/questions/49215866/what-is-difference-between-private-and-public-claims-on-jwt
    * https://idea-instructions.com/public-key/
    * https://medium.com/@jad.karaki/identity-management-saml-vs-oauth2-vs-openid-connect-c9a06548b4c5
    * https://hackernoon.com/demystifying-oauth-2-0-and-openid-connect-and-saml-12aa4cf9fdba
    * https://sectigostore.com/blog/5-differences-between-symmetric-vs-asymmetric-encryption
    * https://portswigger.net/web-security/csrf
    * https://www.keycdn.com/blog/difference-between-http-and-https
    * https://www.cloudflare.com/learning/ssl/why-is-http-not-secure/
    * https://www.geeksforgeeks.org/rsa-algorithm-cryptography
    * https://www.checkmarx.com/knowledge/knowledgebase/session-fixation
    * https://portswigger.net/web-security/cross-site-scripting
    * https://www.ptsecurity.com/ww-en/analytics/knowledge-base/how-to-prevent-sql-injection-attacks/
    * [Session Fixation - how to hijack a website using session fixation method](https://www.youtube.com/watch?v=eUbtW0Z0W1g)
    * [SSL/TLS for Mortals by Maarten Mulders](https://www.youtube.com/watch?v=yJrJEvvW_HA)
    * [The Hacker's Guide to JWT Security by Patrycja Wegrzynowicz](https://www.youtube.com/watch?v=dq39w4MiZzs)
    * [GOTO 2020 • OAuth and OpenID Connect in Plain English • Nate Barbettini](https://www.youtube.com/watch?v=sSy5-3IkXHE)
    * [2019 - Grzegorz Krol - Uwierzytelnienie oraz Autoryzacja w Świecie Mediów i Dostawców Tożsamości](https://www.youtube.com/watch?v=HJhbAxtqFnk)
    * https://jwt.io/introduction/
    * https://auth0.com/docs/secure/tokens/json-web-tokens/json-web-token-claims
    * https://auth0.com/docs/get-started/authentication-and-authorization-flow/authorization-code-flow-with-proof-key-for-code-exchange-pkce
    * https://oauth.net/2/pkce/
    * https://www.oauth.com/oauth2-servers/pkce/authorization-request/
    * https://dropbox.tech/developers/pkce--what-and-why-
    * https://oauth.net/2/grant-types/implicit/
    * https://developer.okta.com/blog/2019/08/22/okta-authjs-pkce
    * https://www.f5.com/labs/articles/cisotociso/securing-apis-in-banking-with-oauth-and-pkce
    * https://docs.wso2.com/display/IS530/Mitigating+Authorization+Code+Interception+Attacks
    * https://blog.netcetera.com/the-idea-behind-mitigation-of-oauth-2-0-code-interception-attacks-15de246cce41
    * https://security.stackexchange.com/questions/175465/what-is-pkce-actually-protecting
    * https://developer.okta.com/docs/concepts/oauth-openid/#is-your-client-public
    * https://stackoverflow.com/questions/16321455/what-is-the-difference-between-the-oauth-authorization-code-and-implicit-workflo
    * https://www.scottbrady91.com/oauth/client-authentication-vs-pkce
    * https://developers.onelogin.com/openid-connect/guides/auth-flow-pkce
    * https://stackoverflow.com/questions/70767605/understanding-benefits-of-pkce-vs-authorization-code-grant
    * https://medium.com/identity-beyond-borders/auth-code-flow-with-pkce-a75ee203e242
    * https://stackoverflow.com/questions/74174249/redirect-url-for-authorization-code-design-flaw-in-spec
    * https://stackoverflow.com/questions/67812472/oauth-authorization-code-flow-security-question-authorization-code-intercepted
    * https://stackoverflow.com/questions/58872488/where-is-the-oauth-access-token-stored-in-the-browser-in-case-of-authorization-c
    * https://spring.io/blog/2023/05/24/spring-authorization-server-is-on-spring-initializr
    * https://chatgpt.com/
    * [SSL/TLS for Mortals by Maarten Mulders](https://www.youtube.com/watch?v=yJrJEvvW_HA)
    * [10 Excellent Ways to Secure Your Spring Boot Application by Brian Vermeer & Matt Raible](https://www.youtube.com/watch?v=PpqNMhe4Bd0)
    * [2019 - Grzegorz Krol - Uwierzytelnienie oraz Autoryzacja w Świecie Mediów i Dostawców Tożsamości](https://www.youtube.com/watch?v=HJhbAxtqFnk)
    * [The Hacker's Guide to JWT Security by Patrycja Wegrzynowicz](https://www.youtube.com/watch?v=dq39w4MiZzs)
    * [Modern Identity Management in the Era of Serverless and Microservices by Mercedes Wyss](https://www.youtube.com/watch?v=3_4B22rysPQ)
    * [Implementing Microservices Security Patterns & Protocols by Joe Grandja, Adib Saikali](https://www.youtube.com/watch?v=nrmQH5SqraA)
    * [GOTO 2020 • OAuth and OpenID Connect in Plain English • Nate Barbettini](https://www.youtube.com/watch?v=sSy5-3IkXHE)
    * [282. WJUG - Jacek Milewski "Hasła - czy to Ty je łamiesz moim użytkownikom?" [PL]](https://www.youtube.com/watch?v=DOSbgZFqLtM)
    * [The Secrets of OAuth 2.0 Part 1/2 • Aaron Parecki & Eric Johnson • GOTO 2020](https://www.youtube.com/watch?v=HhwUMESAddM)
    * [Spring Security: The Good Parts by Daniel Garnier-Moiroux](https://www.youtube.com/watch?v=TrCLf9zAQfs)
    * [What's (not so) new in the new OWASP Top 10 • Tomasz Wrobel • Devoxx Poland 2022](https://www.youtube.com/watch?v=9YU6A4q9mc8)
    * [2023 - Łukasz Wojtach - Królewna Śnieżka i siedmiu współbieżnych krasnoludków](https://www.youtube.com/watch?v=chaS4bFwuSY)
    * [[VDCLUJ2023] Brian Vermeer - Stranger Danger: Your Java Attack Surface Just Got Bigger](https://www.youtube.com/watch?v=KtU2S5ReUhA)
    * [OAuth2, OpenID: live coding SSO, from first principles By Daniel Garnier Moiroux](https://www.youtube.com/watch?v=wP4TVTvYL0Y)
    * [IAM Doomsday Prepper: Surviving the Apocalypse with Keycloak By Maik Kingma](https://www.youtube.com/watch?v=aZOoH0i4s-0)
    * [Securing Your Java Containers by Breaking In By Brian Vermeer](https://www.youtube.com/watch?v=O33z-CWVNpA)
    * [Keep your dependencies up to date with Renovate By Michael Vitz](https://www.youtube.com/watch?v=q43LmW1b2O0)
    * [SEVEN things about API security By Philippe De Ryck](https://www.youtube.com/watch?v=xFzaFo0MiH8)
    * [Introduction to OAuth 2.0 and OpenID Connect By Philippe De Ryck](https://www.youtube.com/watch?v=ZuQoN2x8T6k)
    * [Do you really know JWT? by Karim Pinchon](https://www.youtube.com/watch?v=1dJwKVkrRJo)
    * [The Past, Present, and Future of Cross-Site/Cross-Origin Request Forgery by Dr Philippe De Ryck](https://www.youtube.com/watch?v=K903vmJI-1U)
    * [The insecurity of OAuth 2.0 in frontends - Philippe de Ryck - NDC Security 2023](https://www.youtube.com/watch?v=OpFN6gmct8c)
    * [The Insecurity of OAuth 2.0 in Frontends](https://www.youtube.com/watch?v=2nVYLruX76M)
    * [Getting API security right - Philippe De Ryck - NDC London 2023](https://www.youtube.com/watch?v=7UBm8QFTaq0)

## preface
* goals of this workshop
* workshop plan
    * simulation
        * https://www.oauth.com/playground/authorization-code.html
        * https://www.oauth.com/playground/authorization-code-with-pkce.html
    * server part
        1. run server
        1. generate verifier and hash it
            ```
            sIbiEo4WKEXWVJmRYJBEanLpt5eRD3kodIMYyo7Ywx-w6P_T // verifier
            j8mJ_BqaR97Bc-C0PGD4lZCgp45d4dQvmqEjRbdJ474 // challenge
            ```
        1. authorize
            ```
            http://localhost:8085/oauth2/authorize
            ?response_type=code &client_id=pkce-client
            &redirect_uri=http://127.0.0.1:8080/login/oauth2/code/pkce
            &scope=openid%20email%20profile
            &code_challenge=j8mJ_BqaR97Bc-C0PGD4lZCgp45d4dQvmqEjRbdJ474
            &code_challenge_method=S256
            ```
        1. use code from redirect response
        1. get token
            ```
            curl -X POST http://localhost:8085/oauth2/token \
            -H "Content-Type: application/x-www-form-urlencoded" \
            -H "Authorization: Basic cGtjZS1jbGllbnQ6b2JzY3VyYQ==" \
            -d "grant_type=authorization_code" \
            -d "code=2Zg-8Vhe9C28eYf6Sk0ai4BK77Ybmsy4yRi1wPqnFHGIrIfpk45btmI_1oDbJc4-orUWmpim-K-GLi9uULbuTdcAcF6Ss7LF0j508KYmbNOPGvENjCn5gMuWNjA-BZqF" \
            -d "redirect_uri=http://127.0.0.1:8080/login/oauth2/code/pkce" \
            -d "code_verifier=sIbiEo4WKEXWVJmRYJBEanLpt5eRD3kodIMYyo7Ywx-w6P_T"
            ```
            * change `clientAuthenticationMethod` from `CLIENT_SECRET_POST` to `CLIENT_SECRET_POST`
                ```
                curl -X POST http://localhost:8085/oauth2/token \
                -H "Content-Type: application/x-www-form-urlencoded" \
                -d "client_id=pkce-client" \
                -d "client_secret=obscura" \
                -d "grant_type=authorization_code" \
                -d "code=2Zg-8Vhe9C28eYf6Sk0ai4BK77Ybmsy4yRi1wPqnFHGIrIfpk45btmI_1oDbJc4-orUWmpim-K-GLi9uULbuTdcAcF6Ss7LF0j508KYmbNOPGvENjCn5gMuWNjA-BZqF" \
                -d "redirect_uri=http://127.0.0.1:8080/login/oauth2/code/pkce" \
                -d "code_verifier=sIbiEo4WKEXWVJmRYJBEanLpt5eRD3kodIMYyo7Ywx-w6P_T"
                ```
        1. use token to access `http://localhost:8085/userinfo`
        1. verify public endpoints
            * http://localhost:8085/oauth2/jwks
                * verify that public key is RSA
            * http://localhost:8085/.well-known/oauth-authorization-server
                * verify issuer, authorization_endpoint, token_endpoint, jwks_uri
            * http://localhost:8085/.well-known/openid-configuration
                * verify issuer, authorization_endpoint, token_endpoint, jwks_uri
    * server + client
        1. run server
        1. run client
        1. configure insomnia
            ```
            Grant Type: Authorization Code
            Authorization Url: http://localhost:8085/oauth2/authorize
            Access Token Url: http://localhost:8085/oauth2/token
            Client Id: pkce-client
            Client Secret: obscura
            Use PKCE: yes
            Code Challenge Method: SHA-256
            Redirect Url: http://127.0.0.1:8080/login/oauth2/code/pkce
            Scope: profile openid email
            Credentials: As Basic Auth Header (default)
            ```
        1. access client: `http://127.0.0.1:8080/`
            * don't use localhost
        1. authorize and you should see i

## basics
* authentication
    * process leading to identification
* authorization
    * leading to grant access
* http vs https
    * HTTP sends data over port 80 while HTTPS uses port 443
    * HTTPS uses TLS (SSL) to encrypt normal HTTP requests and responses
* encoding vs encrypting vs hashing
    * encoding
        * any transformation of a given input
        * function: `x -> y`
    * encryption
        * type of encoding
            * to obtain the output: input + key
        * function: `(x, publicKey) -> y`
        * decryption: `(y, privateKey) -> x`
        * symmetric key: `publicKey == privateKey`
        * asymmetric keys: two different keys
    * hashing
        * type of encoding
        * function is only one way (cannot get back the input x)
        * sometimes the hashing function could also use a random value
            * `(x, salt) -> y`
            * salt makes the function stronger

## token
* token ~ access card
    * analogy
        1. when you visit an office building, you first go to the reception desk
        1. you identify yourself (authentication), and you receive an access card (token)
        1. you can use the access card to open some doors, but not necessarily all doors
        1. card is assigned for a certain period (ex. one day)
    * application obtains a token as a result of the authentication process and to access resources
    * application uses them to prove it has authenticated a user
    * tokens can even be regular strings
        * example: UUID
    * steps
        1. X authenticates with his credentials
        1. app generates a token
        1. app returns the token to X
        1. X wants to access his resources
            * client sends the access token in the request
        1. app validates token
        1. if token is valid - return resources
    * advantages
        * help avoiding credentials sharing in all requests
            * more often you expose the credentials, the bigger the chances are that
              someone intercepts them
            * example: HTTP Basic assumes you send credentials for each request
        * could be created with a short lifetime
            * if someone steals the token, he won’t be able to use it forever
                * token might expire before they find out how to use it
        * could be invalidated without invalidating the credentials
            * people tend to have the same credentials for multiple apps
        * could store additional details
            * replaces a server-side session with a client-side session
                * better flexibility for horizontal scaling
            * example: stores user roles
        * delegate authentication responsibility to another component (authorization server)
            * we could implement a system that doesn’t manage its own users
            * allows users to authenticate using credentials from GitHub, Twitter, and so on
            * enhance scalability
            * makes the system architecture more natural to understand and develop
* JSON Web Token (JWT)
    * is an open standard
    * compact and self-contained way for securely transmitting information between parties as a JSON object
    * pronunciation: jot
    * https://jwt.io/
        * typically looks like this: `xxxxx.yyyyy.zzzzz`
        * three parts separated by a dot
            * header
                * formatted as JSON + Base64 encoded
                ```
                { // store metadata related to the token
                    "alg": "HS256", // algorithm that generates the signature
                    "typ": "JWT" // the type of the token
                }
                ```
            * payload
                * formatted as JSON + Base64 encoded
                ```
                {
                    "sub": "1234567890",
                    "name": "John Doe",
                    "admin": true
                }
                ```
                * contains the claims - statements about user and additional data
                    * registered claims
                        * predefined claims which are not mandatory but recommended
                        * important ones
                            * `iss` (issuer): issuer of the JWT
                            * `sub` (subject): subject of the JWT (the user)
                            * `aud` (audience): recipient for which the JWT is intended
                            * `exp` (expiration time): time after which the JWT expires
                    * public claims
                        * defined for public consumption
                        * required to be collision resistant
                        * should be well documented
                    * private claims
                        * known only to the producer and consumer of a JWT
                    * always validate claims even if signature is valid
            * signature
                ```
                HMACSHA256( // example with HMAC SHA256 algorithm
                    base64UrlEncode(header) + "." +
                    base64UrlEncode(payload),
                    secret
                )
                ```
                * used to verify the message wasn't changed along the way
                * if signed with a private key, it can also verify the sender of the JWT
                * can be missing
                * when a JWT is signed, we also call it a JWS (JSON Web Token Signed)
                    * if a token is encrypted, we also call it a JWE (JSON Web Token Encrypted)
        * there’s 4 algorithms that can be used to sign a JWT (seal our envelope)
            * HMAC (symmetric)
            * RSA (asymmetric)
            * ESDSA (asymmetric)
            * None (no signature)
                * not supposed to be used for a production environment
            * ideal configuration: disable all algorithms that are not being used and specially
                * substitution attack
                    1. attacker authenticates to a web server with valid credentials
                    1. web server generates a JWT and signs it with an RSA private key
                    1. JWT is passed on to the attacker
                    1. attacker tampers with the JWT
                        1. downloads the public key
                            * public key is exposed on an endpoint such as /.well-known/jwks.json
                        1. changes JWT
                        1. signs the JWT with the exposed public key
                        1. changes the encryption algorithm to HMAC
                        1. sends the request across
                    1. tampered JWT has been signed with the exposed public key, and the algorithm in use is HMAC, the JWT gets validated
                        * HMAC is a symmetrical encryption
        * keep the token as short as possible
            * if the token is long, it slows the request
            * the longer the token, the more time the cryptographic algorithm needs for signing it
        * frontend
            * chrome -> dev tools -> application -> storage
            * securing token in the browser alone is not possible
                * stealing data from storage areas is a trivial attack
                * solution: backend for frontend (BFF)
                    * bff proxies api calls and replaces cookies with tokens
                    * attacker has no longer direct access to security token service
                    * compromised frontend app can still send request through bff (aka session riding)
                        * bff reduces consequences of attack to session riding
                            * only endpoints exposed by bff can be abused
                            * attacker never has unfettered access to the apis
                            * bff observes all the api requests from a client and can perform rate-limiting, anomaly detection etc
            * storage
                * HttpOnly cookie
                    * not accessible via JavaScript, reducing the risk of XSS attacks
                    * recommended
                        * CSRF is possible if the application doesn’t apply any CSRF protection mechanism
                            * using cookies = vulnerable by default
                            * SameSite cookies
                                * adds a flag for the browser: that cookie is intended for same site request only
                                * are not included on cross-site requests
                                    * attacker can still send the request, but cookie-based authentication state will not be included by the browser
                                * Chrome is using SameSite cookie as default behaviour
                                * problem: SameSite cookies cannot protect against Cross-Origin Request Forgery
                                    * SameSite cookies effectively mitigate Cross-Site Request Forgery attacks
                                    * attacker: launch attack from subdomain of your site
                                        * why would we ever give an attacker control over a subdomain?
                                            * Rampant CNAME misconfiguration leaves thousands of organizations open to subdomain takeover attacks
                                                * DNS wrongly configured - CNAME points to some cloud resource
                                                * there are some unused entries that attacker can register once again to point to his malicious site
                                                    * dangling subdomains
                            * defense summary
                                ![alt text](img/security/csrf_defense_summary.png)
                                * synchronizer tokens
                                    * server returns response with secret + cookie
                                        * you need to send that secret to server as part of request: `url=...&csrf_token=530_ea8`
                                    * attacker cannot read it as secret is in victim browser and no outside
                                        * so standard attack is undoable
                                        * same-origin policy prevents a malicious page from stealing a legitimate token from a page
                                            * ensures that a malicious page from a different domain cannot read the anti-CSRF token from the target site
                                                * it cannot make cross-origin requests
                                    * problem: requires explicit implementation effort and is often forgotten or omitted
                * in-memory storage
                    * doesn't persist tokens across page reloads or browser sessions
                        * reauthorize when reloading the page
                    * accessible via JavaScript and vulnerable to XSS attacks
                * session storage
                    * cleared when the page session ends (typically when the tab or window is closed)
                    * accessible via JavaScript and vulnerable to XSS attacks

## oauth2
* oauth1
    * signature process is complex and difficult to implement correctly
        * less flexible for different types of clients and use cases
    * token handling less straightforward
        * two types of tokens: request token, access token
    * limited adoption
* used for delegated authorization
    * how can I allow an app to access my data without necessarily giving it my password?
    * use cases
        * Spotify trying to access your facebook friends list to import it into Spotify
        * keep posts for linkedin and twitter in a buffer, schedule them and post on twitter and linkedin on a given hour
        * authorize some website to access pictures hosted on Google Photos without sharing his Google password
* implementations: Keycloak, Okta
* defines four roles
    * Resource Owner
        * the user himself
        * entity that can agree to provide access to a protected resource
    * Client
        * application requesting access to a resource server
        * typically web application calling an api or an api calling an api
    * Authorization Server
        * stores the user's and client's credentials
            * client credentials: allows known applications to be authorized by it
        * server issuing access token to the client
        * token will be used for the client to request the resource server
    * Resource Server
        * server hosting protected data
            * example: Facebook hosting your profile and personal information
        * client obtains an access token from the authorization server
            * adds the token to the HTTP request headers (to resource server)
        * three options for implementing token validation at the resource server level
            * resource server directly call the authorization server to verify an issued token
                * remember the rule of thumb: the network is not 100% reliable
            * shared database where the authorization server stores tokens
                * resource server can access and validate the tokens
                * also called blackboarding
                * database might become a bottleneck
            * cryptographic signatures
                * authorization server signs the token when issuing it
                    * resource server validates the signature
                * authorization server uses a private key to sign it
                * resource server uses a public key to verify signature
                * commonly used
                    * google, twitter etc
                        * https://developer.github.com/apps/building-oauth-apps/authorizing-oauth-apps/
* scopes
    * allow user to delegate subset of their full authority to a client application
    * define the scope of an access token
    * space delimited string
      * example: `scope=opendid email profile read:reviews`
      * github has granular scopes like: "invite ppl to repo" etc
    * OAuth2 does not define any scope values
        * OIDC has a set of reserved scopes
* flows
    * authorization code flow
        * exchanges an authorization code for a token
            * alongside with app’s Client Secret
        * steps
            1. user clicks on a login link in the web application
            1. user is redirected to an OAuth authorization server
            1. user provides credentials
                * typically, the user is shown a list of permissions that will be granted
            1. user is redirected to the application, with a one-time short-lived authorization code
                * authorization code will be available in the `code` URL parameter
                    * from specification: authorization code will be sent via HTTP 302 "redirect" URL to the client
                * why authorization code is returned and not the token itself?
                    * prevents replay attacks
                        * note that authorization code is used exactly once
                            * in many scenarios that an attacker might get access to the code, it's already been exchanged
                            for an access token and therefore useless
            1. app receives the user’s authorization code
                * forwards it along with the Client ID and Client Secret, to the OAuth authorization server
                    * why to not pass client secret in the first step?
                        * keeps sensitive information (client secret) from the browser
                            * you could not trust the client (user/his browser which try to use you application)
            1. authorization server sends an ID Token, Access Token, and an optional Refresh Token
                * refresh tokens
                    * token that doesn’t expire is too powerful
                    * to obtain a new access token, the client can rerun the flow
                        * not really user friendly
                        * example: 20-minute lifespan
                            * app would redirect back about three times every hour to log in again
                    * used to obtain a new access token instead of re-authentication
                        * storing the refresh token is safer: you can revoke it if you find that it was exposed
                    * should be considered as sensitive as user credentials
                        * nuanced: using refresh token requires client authentication
                            * but in mobiles / public client you don't have client credentials - so only refresh token
                            * when attacker gains access to both, users are in major trouble
                    * minimum security requirement: guaranteeing confidential storage
                        * move refresh tokens to an isolated service in architecture
                            * main application can request a new access token from this service
                            * only service has access to the encrypted refresh tokens and associated keys
                    * refresh token rotation
                        * each refresh gives new token and **new refresh token**: `rf1 -> (at2, rf2)`
                            * detect refresh token abuse: if refresh token was reused => invalidate new tokens immediately
                                * what if stolen token is never used twice?
                                  * security relies on seeing token twice
                                  * scenario: attacker steals token and waits until application goes offline (user closed app, is on the airplane etc)
            1. web application can then use the Access Token to gain access to the target API
    * to mitigate the risk of stealing authorization code you can use PKCE
        * stands for: Proof Key for Code Exchange
        * problem with standard authorization code flow
            * intercepting authorization code + public client
                * opposite of confidential client
                    * no real way of authenticating themselves
                * example
                    * native apps
                        * decompiling the app will reveal the Client Secret
                            * bound to the app and the same for all users and devices
                        * malicious app is registered with the same custom URI (redirect URI) as the legitimate app
                            ![txt](img/stealing_auth_code.png)
                    * single-page apps
                        * entire source is available to the browser
                    * called public clients (when an end user could view and modify the code)
                        * they do not have a real way of authenticating themselves
        * is not a replacement for a client secret
            * is recommended even if a client is using a client secret
            * allows the authorization server to validate: client exchanging the authorization code == same client that requested it
        * how it works
            * in place of the `client_secret`, the client app creates a unique string value, `code_verifier`
            * `code_challenge` = hashed and encoded `code_verifier`
            * when the client app initiates the first part of the Authorization Code flow, it sends a hashed `code_challenge`
            * then the client app requests an `access_token` in exchange for the authorization code
                * client app must include the original unique string value in the `code_verifier`
            * communication between the client and authorization server should be through a secured channel(TLS)
            so the codes cannot be intercepted
    * other
        * Client Credentials flow
            * no user involved
                * used for non-user flows like: scheduled cron jobs, github actions, configuration tools
            * identity tokens are not used
                * Oauth2 only, not an OIDC
            * works only with confidential clients
            * no refresh token
                * client can use its own credentials to obtain a new access token at any time
        * Implicit and Hybrid flow
            * avoid the authorization code exchange => significantly harder to secure

## OpenId Connect (OIDC)
* allows for "Federated Authentication"
    * example: Federated Authentication is logging to Spotify using your facebook credentials
* current practice
    * asking for permissions - OAuth 2.0
        * Delegated Authorization
        * most OAuth2 servers also implement OpenId Connect
    * authentication and single-sign on - OpenID Connect
        * Federated Authentication
* authentication protocol built on top of OAuth2, JWT and TLS
    * defines a standarized user identity token as JWT with required fields
        * iss - who issues the token
        * iat - time when the token was issued
        * exp - time when the token expires
        * sub - unique id of the user that the token represents
        * aud - list of systems that can use the token
    * defines a userinfo endpoint that clients can call to learn details about the user
        * example: email address, profile, contact info