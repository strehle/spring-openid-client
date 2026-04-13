package org.cloudfoundry.identity.spring.web.springdemo;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jose.util.X509CertUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.client.endpoint.NimbusJwtClientAuthenticationParametersConverter;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.oauth2.client.endpoint.RestClientAuthorizationCodeTokenResponseClient;
import org.springframework.security.oauth2.client.oidc.web.logout.OidcClientInitiatedLogoutSuccessHandler;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Optional;
import java.util.UUID;
import java.util.function.Function;

@Configuration
@EnableWebSecurity
public class WebSecurityConfig {

  @Autowired
  private ClientRegistrationRepository clientRegistrationRepository;

  @Value("${appconfig.appurl}")
  private String appUrl;

  @Value("${appconfig.private-key}")
  private String privateKeyPem;

  @Value("${appconfig.certificate}")
  private String publicCertPem;

  private JWK privateJwk;
  /** SHA-1 thumbprint of the certificate, used as x5t header value for Azure AD */
  private Base64URL sha1Thumbprint;

  @Bean
  public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
    Security.addProvider(new BouncyCastleProvider());

    http
        .csrf(csrf -> csrf.disable())
        .authorizeHttpRequests(auth -> auth
            .requestMatchers("/secured/**").authenticated()
            .anyRequest().permitAll()
        )
        .logout(logout -> logout.logoutSuccessHandler(oidcLogoutSuccessHandler()))
        .oauth2Login(oauth2 -> oauth2
            .tokenEndpoint(token -> token
                .accessTokenResponseClient(accessTokenResponseClient())
            )
        );

    return http.build();
  }

  private LogoutSuccessHandler oidcLogoutSuccessHandler() {
    OidcClientInitiatedLogoutSuccessHandler oidcLogoutSuccessHandler =
        new OidcClientInitiatedLogoutSuccessHandler(
            this.clientRegistrationRepository);

    oidcLogoutSuccessHandler.setPostLogoutRedirectUri(appUrl);

    return oidcLogoutSuccessHandler;
  }

  private RestClientAuthorizationCodeTokenResponseClient accessTokenResponseClient() {
    NimbusJwtClientAuthenticationParametersConverter<OAuth2AuthorizationCodeGrantRequest> converter =
        new NimbusJwtClientAuthenticationParametersConverter<>(jwkResolver);
    /**
     * This client_assertion change is needed only for Azure AD
     */
    converter.setJwtClientAssertionCustomizer((context) -> {
      // x5t is the SHA-1 thumbprint required by Azure AD; sha1Thumbprint is populated by jwkResolver
      if (sha1Thumbprint != null) {
        context.getHeaders().header("x5t", sha1Thumbprint.toString());
      }
    });
    /**
     * Other OIDC providers simply rely on kid and do not need the customizer above
     */

    RestClientAuthorizationCodeTokenResponseClient tokenResponseClient =
        new RestClientAuthorizationCodeTokenResponseClient();
    tokenResponseClient.addParametersConverter(converter);
    return tokenResponseClient;
  }

  private Function<ClientRegistration, JWK> jwkResolver = (clientRegistration) -> {
    if (clientRegistration.getClientAuthenticationMethod().equals(ClientAuthenticationMethod.PRIVATE_KEY_JWT)) {
      if (privateJwk != null) {
        return privateJwk;
      }
      RSAPublicKey publicKey;
      RSAPrivateKey privateKey;
      try {
        X509Certificate x509 = X509CertUtils.parse(publicCertPem);
        sha1Thumbprint = Optional.ofNullable(computeSHA1Thumbprint(x509))
            .orElse(new Base64URL(UUID.randomUUID().toString()));
        Base64URL x5tS256 = Optional.ofNullable(computeSHA256Thumbprint(x509))
            .orElse(new Base64URL(UUID.randomUUID().toString()));
        publicKey = JWK.parse(x509).toRSAKey().toRSAPublicKey();
        privateKey = JWK.parseFromPEMEncodedObjects(privateKeyPem).toRSAKey().toRSAPrivateKey();
        privateJwk = new RSAKey.Builder(publicKey)
            .privateKey(privateKey)
            .keyID(x5tS256.toString())
            .x509CertSHA256Thumbprint(x5tS256)
            .build();
      } catch (JOSEException e) {
        throw new RuntimeException(e);
      }
      return privateJwk;
    }
    return null;
  };

  public static Base64URL computeSHA1Thumbprint(final X509Certificate cert) {
    try {
      if (cert == null) {
        return null;
      }
      byte[] derEncodedCert = cert.getEncoded();
      MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
      return Base64URL.encode(sha1.digest(derEncodedCert));
    } catch (NoSuchAlgorithmException | CertificateEncodingException e) {
      return null;
    }
  }

  public static Base64URL computeSHA256Thumbprint(final X509Certificate cert) {
    try {
      if (cert == null) {
        return null;
      }
      byte[] derEncodedCert = cert.getEncoded();
      MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
      return Base64URL.encode(sha256.digest(derEncodedCert));
    } catch (NoSuchAlgorithmException | CertificateEncodingException e) {
      return null;
    }
  }
}
