# แนวทางการพัฒนา Authorization Server ด้วย Spring Boot 4.0.1 & Spring Security 7.0.2

โปรเจกต์ตัวอย่างการสร้าง **OAuth2 Authorization Server** โดยใช้โครงสร้างล่าสุด รองรับ **Java 25** และการตั้งค่าแบบใหม่ (Explicit Configuration) 

## 🛠️ Stack Components
* **Java:** 25
* **Framework:** Spring Boot 4.0.1
* **Security:** Spring Security 7.0.2
* **Build Tool:** Gradle (Groovy)
* **Database:** Postgres 16+

---

## 🏗️ Configuration (SecurityConfig.java)

การตั้งค่าใน Spring Security 7.x จะไม่ใช้ `OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http)` อีกต่อไป แต่จะเปลี่ยนมาใช้แนวทางนี้แทน:

```java
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    @Order(1)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
        // 1. สร้าง Configurer ใหม่
        OAuth2AuthorizationServerConfigurer authServerConfigurer = new OAuth2AuthorizationServerConfigurer();

        http
            .securityMatcher(authServerConfigurer.getEndpointsMatcher())
            .with(authServerConfigurer, (authorizationServer) ->
                authorizationServer
                    .oidc(Customizer.withDefaults()) // เปิดใช้งาน OpenID Connect 1.0
            )
            .authorizeHttpRequests((authorize) ->
                authorize.anyRequest().authenticated()
            )
            // กำหนดหน้า Login สำหรับ User (Resource Owner)
            .formLogin(Customizer.withDefaults());

        return http.build();
    }

    @Bean
    @Order(2)
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests((authorize) -> authorize
                .anyRequest().authenticated()
            )
            .formLogin(Customizer.withDefaults());
            
        return http.build();
    }

    @Bean
    public RegisteredClientRepository registeredClientRepository() {
        RegisteredClient oidcClient = RegisteredClient.withId(UUID.randomUUID().toString())
            .clientId("oidc-client")
            .clientName("OIDC Debugger Client")
            .clientSecret("{noop}secret")
            .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
            .redirectUri("https://oidcdebugger.com/debug")
            .scope(OidcScopes.OPENID)
            .scope(OidcScopes.PROFILE)
            .clientSettings(ClientSettings.builder()
                .requireAuthorizationConsent(true)
                .requireProofKey(true)
                .build())
            .tokenSettings(TokenSettings.builder()
                .accessTokenTimeToLive(Duration.ofMinutes(30))
                .reuseRefreshTokens(false)
                .build())
            .build();

        return new InMemoryRegisteredClientRepository(oidcClient);
    }

    @Bean
    public JWKSource<SecurityContext> jwkSource() {
        KeyPair keyPair = generateRsaKey();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        RSAKey rsaKey = new RSAKey.Builder(publicKey)
            .privateKey(privateKey)
            .keyID(UUID.randomUUID().toString())
            .build();
        JWKSet jwkSet = new JWKSet(rsaKey);
        return new ImmutableJWKSet<>(jwkSet);
    }

    private static KeyPair generateRsaKey() { 
        KeyPair keyPair;
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            keyPair = keyPairGenerator.generateKeyPair();
        } catch (Exception ex) {
            throw new IllegalStateException(ex);
        }
        return keyPair;
    }

    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings.builder().build();
    }

    @Bean
    public UserDetailsService userDetailsService() {
        
        UserDetails user = User.builder()
            .username("user")
            .password("{noop}password")
            .roles("USER")
            .build();
        
        UserDetails admin = User.builder()
            .username("admin")
            .password("{noop}password")
            .roles("USER", "ADMIN")
            .build();
        
        return new InMemoryUserDetailsManager(user, admin);
    }
}
```
---

## 🔗 Metadata Endpoints
เมื่อรันแอปพลิเคชันแล้ว คุณสามารถตรวจสอบสถานะ Config ได้ที่:

OIDC Discovery: http://localhost:8080/.well-known/openid-configuration

Public Keys (JWKS): http://localhost:8080/oauth2/jwks

---

## 🧪 การทดสอบด้วย OIDC Debugger
สามารถทดสอบ Flow การขอรหัส (Authorization Code Flow) ได้ที่ oidcdebugger.com

ตั้งค่าในหน้า OIDC Debugger:
**1. Authorize URI:** http://localhost:8080/oauth2/authorize

**2. Redirect URI:** https://oidcdebugger.com/debug

**3. Client ID:** oidc-client (ต้องตรงกับที่ Config ใน RegisteredClientRepository)

**4. Scope:** openid profile

**5. Response type:** code

**6. Response mode:** query
