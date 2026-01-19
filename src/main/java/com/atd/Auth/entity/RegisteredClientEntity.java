package com.atd.Auth.entity;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;
import java.time.Instant;

@Entity
@Table(name = "oauth2_registered_client")
@Getter @Setter
public class RegisteredClientEntity {
    @Id
    private String id;
    private String clientId;
    private Instant clientIdIssuedAt = Instant.now();
    private String clientSecret;
    private Instant clientSecretExpiresAt;
    private String clientName;

    @Column(length = 1000)
    private String clientAuthenticationMethods;

    @Column(length = 1000)
    private String authorizationGrantTypes;

    @Column(length = 1000)
    private String redirectUris;

    @Column(length = 1000)
    private String postLogoutRedirectUris;

    @Column(length = 1000)
    private String scopes;

    @Column(length = 2000)
    private String clientSettings;

    @Column(length = 2000)
    private String tokenSettings;
}