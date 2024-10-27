package br.assistentediscente.authserver.configuration;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;

@Configuration
public class AuthorizationServerConfig {

    private final RSAProperties rsaProperties;
    public AuthorizationServerConfig(RSAProperties rsaProperties, RSAProperties rsaProperties1) {
        this.rsaProperties = rsaProperties1;
    }

    @Bean
    AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings.builder()
                .issuer(rsaProperties.getIssuerUri())
                .build();
    }

}
