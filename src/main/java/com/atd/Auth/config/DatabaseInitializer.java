package com.atd.Auth.config;

import java.time.Duration;
import java.util.Set;
import java.util.UUID;

import com.atd.Auth.entity.UserEntity;
import com.atd.Auth.repository.UserRepository;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;

@Configuration
public class DatabaseInitializer implements CommandLineRunner {

    private final RegisteredClientRepository registeredClientRepository;

    private final UserRepository userRepository;

    private final PasswordEncoder passwordEncoder;

    // รวมการฉีด Dependency ไว้ใน Constructor เดียว
    public DatabaseInitializer(
            RegisteredClientRepository registeredClientRepository, UserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.registeredClientRepository = registeredClientRepository;
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public void run(String... args) throws Exception {
        // Initial OIDC Client
        initializeOidcClient();

        initializeUsers();
    }

    private void initializeOidcClient() {
        if (registeredClientRepository.findByClientId("oidc-client") == null) {
            RegisteredClient registeredClient = RegisteredClient.withId(UUID.randomUUID().toString())
                    .clientId("oidc-client")
                    .clientName("OIDC Debugger Client")
                    .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                    .clientSecret(passwordEncoder.encode("secret")) // แนะนำให้เข้ารหัสแทน {noop}
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

            registeredClientRepository.save(registeredClient);
        }

        if (registeredClientRepository.findByClientId("spa-client") == null) {
            RegisteredClient spaClient =
                    RegisteredClient.withId(UUID.randomUUID().toString())
                            .clientId("spa-client")
                            .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
                            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                            .redirectUri("http://localhost:5173/callback")
                            .scope(OidcScopes.OPENID)
                            .scope("profile")
                            .clientSettings(ClientSettings.builder()
                                    .requireProofKey(true)
                                    .build())
                            .build();

            registeredClientRepository.save(spaClient);
        }

        if (registeredClientRepository.findByClientId("admin-client") == null) {
            RegisteredClient adminClient =
                    RegisteredClient.withId(UUID.randomUUID().toString())
                            .clientId("admin-client")
                            .clientSecret(passwordEncoder.encode("secret"))
                            .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                            .redirectUri("http://localhost:8081/login/oauth2/code/admin")
                            .scope(OidcScopes.OPENID)
                            .scope("admin")
                            .build();

            registeredClientRepository.save(adminClient);
        }
    }

    private void initializeUsers() {

        // ---------- Users ----------
        if (userRepository.findByUsername("user").isEmpty()) {
            UserEntity user = new UserEntity();
            user.setUsername("user");
            user.setPassword(passwordEncoder.encode("password"));
            user.setEmail("user@host.local");
            user.setEnabled(true);
            user.setRoles(Set.of("USER"));
            userRepository.save(user);
        }

        if (userRepository.findByUsername("admin").isEmpty()) {
            UserEntity admin = new UserEntity();
            admin.setUsername("admin");
            admin.setPassword(passwordEncoder.encode("password"));
            admin.setEmail("admin@host.local");
            admin.setEnabled(true);
            admin.setRoles(Set.of("ADMIN", "USER"));
            userRepository.save(admin);
        }
    }
}