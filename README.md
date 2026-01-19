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



