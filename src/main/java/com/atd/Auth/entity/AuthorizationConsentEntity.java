package com.atd.Auth.entity;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;

import java.io.Serializable;

@Entity
@Table(name = "oauth2_authorization_consent")
@IdClass(AuthorizationConsentId.class)
@Getter
@Setter
public class AuthorizationConsentEntity {
    @Id
    private String registeredClientId;
    @Id
    private String principalName;

    @Column(length = 1000)
    private String authorities;
}

// Class สำหรับ Composite Primary Key
@Getter @Setter
class AuthorizationConsentId implements Serializable {
    private String registeredClientId;
    private String principalName;
}