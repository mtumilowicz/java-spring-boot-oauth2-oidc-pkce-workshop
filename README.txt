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

## general
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
    * keep the token as short as possible
        * if the token is long, it slows the request
        * the longer the token, the more time the cryptographic algorithm needs for signing it

## oauth2
* delegated authorization
    * how can I allow an app to access my data without necessarily giving it my password?
    * authorization is the ability of an external app to access resources
    * example: Spotify trying to access your facebook friends list to import it into Spotify
* implementations: Keycloak or Okta
* defines four roles:
    * Resource Owner
        * the user himself
    * Client
        * application requesting access to a resource server
    * Authorization Server
        * server issuing access token to the client
        * token will be used for the client to request the resource server
        * stores the user’s and client’s credentials
            * client credentials: allows known applications to be authorized by it
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
* authorization code flow
    * exchanges an authorization code for a token
    * you have to also pass along your app’s Client Secret
    * use cases: Server side web applications where the source code is not exposed publicly
    * steps
        1. user clicks on a login link in the web application
        1. user is redirected to an OAuth authorization server
        1. user provides credentials
            * typically, the user is shown a list of permissions that will be granted
        1. user is redirected to the application, with a one-time authorization code
            * authorization code will be available in the `code` URL parameter
                * from specification: authorization code will be sent via HTTP 302 "redirect" URL to the client
            * why authorization code is returned and not the token itself
                * if the access token would be returned directly (instead of authorization code)
                machine with the browser/app would have access to it
                * don't trust the users machine to hold tokens but you do trust your own servers
            * note that authorization code is used exactly once
                * in many scenarios that an attacker might get access to the code, it's already been exchanged
                for an access token and therefore useless
                * to mitigate the risk of stealing authorization code you can use PKCE
        1. app receives the user’s authorization code
            * forwards it along with the Client ID and Client Secret, to the OAuth authorization server
                * why to not pass client secret in the first step?
                    * you could not trust the client (user/his browser which try to use you application)
                * keeps sensitive information (client secret) from the browser
                * uses secure channel of communication
                    * connection between client application and authorization server is hidden from user
                        * it could be very secured channel not the same as the one from user to client application
        1. authorization server sends an ID Token, Access Token, and an optional Refresh Token
            * in the end the authorization server (e.g: "Login with Facebook") will talk directly with
            he client (say, your server-side BFF) that will ultimately access the resource, so that
            the user-agent never has direct access
        1. web application can then use the Access Token to gain access to the target API
* refresh tokens
    * token that doesn’t expire is too powerful
    * to obtain a new access token, the client can rerun the flow
        * not really user friendly
        * example: 20-minute lifespan
            * app would redirect back about three times every hour to log in again
    * used to obtain a new access token instead of reauthentication
        * storing the refresh token is safer: you can revoke it if you find that it was exposed
* vulnerabilities
    * with a user logged in, CSRF is possible if the application doesn’t apply any CSRF protection mechanism
    * token hijacking

## OpenId Connect
* allows for "Federated Authentication"
* are built using the Oauth2.0 and then adding a few additional steps over
* Federated Authentication is a completely different from Delegated Authorization
    * example: Federated Authentication is logging to Spotify using your facebook credentials
    * distinction is important because OAuth 2.0 flow is designed to "grant authorization" and
      is not meant to be used to "authenticate"

## PKCE
* stands for: Proof Key for Code Exchange
* problem with standard authorization code flow
    1. if hacker intercepts authorization code he could simulate the flow
        * he can use some other client and access your (public) API directly and thus retrieve the
        tokens just the same
    1. what to do if the client secret cannot be kept private?
        * native apps
            * decompiling the app will reveal the Client Secret, which is bound to the app and
            is the same for all users and devices
        * single-page apps
            * cannot securely store a Client Secret because their entire source is available to the browser
        * called public clients (when an end user could view and modify the code)
            * they do not have a real way of authenticating themselves
* is not a replacement for a client secret
    * is recommended even if a client is using a client secret
    * allows the authorization server to validate that the client application exchanging the authorization
    code is the same client application that requested it
* it does not allow treating a public client as a confidential client
* PKCE does not protect against "fake apps"
    * only mitigates the case when another app on the same device try to steal the token that is issued for another app
    * think of a Bank app, it is not good if another app on the device can get the token that the Bank app is using
        * how stealing can be done?
            ![txt](img/stealing_auth_code.png)
            * malicious app is registered with the same custom URI (redirect URI) as the legitimate app
* vs Authorization Code flow: don't require to provide a client_secret
    * reduces security risks for native apps, as embedded secrets aren’t required in source code
* how it works
    * summary
        * in place of the client_secret, the client app creates a unique string value, code_verifier
        * code_challenge = hashed and encoded code_verifier
        * when the client app initiates the first part of the Authorization Code flow, it sends a hashed code_challenge
        * then the client app requests an access_token in exchange for the authorization code
            * client app must include the original unique string value in the code_verifier
        * communication between the client and authorization server should be through a secured channel(TLS)
        so the codes cannot be intercepted
    * steps
        1. user clicks Login within the application
        1. application creates a cryptographically-random code_verifier and code_challenge
            * code_challenge = Base64-URL-encoded string of the SHA256 hash of the code verifier
        1. user is redirected to an OAuth authorization server
        1. user provides credentials
            * typically, the user is shown a list of permissions that will be granted
            * authorization server stores the code_challenge  in the database along with the authorization code
        1. user is redirected to the application, with a one-time authorization code
            * authorization server stores the code_challenge
        1. app receives the user’s authorization code
            * forwards it along with the Client ID and original code_verifier, to the OAuth authorization server
        1. authorization server verifies the code_challenge and code_verifier
        1. authorization server responds with an ID token and access token (and optionally, a refresh token)
        1. application can use the access token to call an API to access information about the user
        1. API responds with requested data

## insomnia
* GET: some service url
* tab Auth: OAuth 2.0
    * Grant Type: Authorization Code
    * Authorization URL: http://localhost:8080/oauth/authorize
    * Access Token URL: http://localhost:8080/oauth/token
    * Client Id: client1
    * Client Secret: secret1


* use: http://127.0.0.1:8080/ not localhost
