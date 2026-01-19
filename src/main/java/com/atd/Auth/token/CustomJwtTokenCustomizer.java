package com.atd.Auth.token;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.stream.Collectors;

@Component
public class CustomJwtTokenCustomizer
        implements OAuth2TokenCustomizer<JwtEncodingContext> {

    @Override
    public void customize(JwtEncodingContext context) {

        Authentication principal = context.getPrincipal();
        if (principal == null) return;

        // ❗ ใช้ ArrayList (mutable)
        List<String> authorities = principal.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toList());

        /* =========================
           Access Token
           ========================= */
        if (OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())) {

            context.getClaims().claim("authorities", authorities);
        }

        /* =========================
           ID Token
           ========================= */
        if (OidcParameterNames.ID_TOKEN.equals(context.getTokenType().getValue())) {

            List<String> roles = authorities.stream()
                    .filter(a -> a.startsWith("ROLE_"))
                    .map(a -> a.substring(5))
                    .collect(Collectors.toList());

            context.getClaims().claim("roles", roles);
        }
    }
}