package br.assistentediscente.authserver.configuration;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;

import java.security.KeyFactory;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

@Configuration
public class TokenStoreConfig {

    private RSAPublicKey publicKey;
    private RSAPrivateKey privateKey;
    private final RSAProperties rsaProperties;

    public TokenStoreConfig(RSAProperties rsaProperties) {
        this.rsaProperties = rsaProperties;
    }

    @Bean
    JWKSource<SecurityContext> jwkSource() {
        generateRsaKey();
        RSAKey rsaKey = new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .keyID(rsaProperties.getKeyId())
                .build();
        JWKSet jwkSet = new JWKSet(rsaKey);
        return new ImmutableJWKSet<>(jwkSet);
    }

    @Bean
    JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }

    private void generateRsaKey() {
        try {
            byte [] keyB = Base64.getDecoder().decode(rsaProperties.getPrivateKey());
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyB);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            privateKey = (RSAPrivateKey) keyFactory.generatePrivate(keySpec);

            byte[] key1B = Base64.getDecoder().decode(rsaProperties.getPublicKey());
            X509EncodedKeySpec keySpec1 = new X509EncodedKeySpec(key1B);
            KeyFactory keyFactory1 = KeyFactory.getInstance("RSA");
            publicKey = (RSAPublicKey) keyFactory1.generatePublic(keySpec1);
        }
        catch (Exception ex) {
            throw new IllegalStateException(ex);
        }
    }
}
