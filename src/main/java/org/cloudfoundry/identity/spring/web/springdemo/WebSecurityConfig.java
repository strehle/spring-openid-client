package org.cloudfoundry.identity.spring.web.springdemo;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jose.util.X509CertUtils;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
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

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.List;
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

  /** Cached JWK instance built from the configured cert + private key */
  private JWK privateJwk;
  /** SHA-1 thumbprint of the certificate, used as x5t header value for Azure AD */
  private Base64URL sha1Thumbprint;

  @Bean
  public SecurityFilterChain securityFilterChain(HttpSecurity http) {
    Security.addProvider(new BouncyCastleProvider());

    http
        .csrf(csrf -> csrf.disable())
        .authorizeHttpRequests(auth -> auth
            .requestMatchers("/secured", "/secured/**").authenticated()
            .anyRequest().permitAll()
        )
        .logout(logout -> logout
            .logoutSuccessHandler(oidcLogoutSuccessHandler())
            .invalidateHttpSession(true)
            .clearAuthentication(true)
            .deleteCookies("JSESSIONID")
        )
        .oauth2Login(oauth2 -> oauth2
            .tokenEndpoint(token -> token
                .accessTokenResponseClient(accessTokenResponseClient())
            )
        );

    return http.build();
  }

  /**
   * Exposes the private JWK as a Spring bean so it can be injected into controllers
   * (e.g. to serve the public key via /jwks_uri).
   * Returns null when no certificate/key is configured; use @Autowired(required=false).
   */
  @Bean
  public JWK privateJwk() {
    return buildJwk();
  }

  // ---------------------------------------------------------------------------
  // Internal helpers
  // ---------------------------------------------------------------------------

  /** Builds (and caches) the JWK from the configured PEM cert + private key. */
  private JWK buildJwk() {
    if (privateJwk != null) {
      return privateJwk;
    }
    try {
      if (publicCertPem == null || publicCertPem.isBlank()
          || privateKeyPem == null || privateKeyPem.isBlank()
          && X509CertUtils.parse(publicCertPem) == null) {
        privateJwk = generateJWK();
        return privateJwk;
      }
      X509Certificate x509 = X509CertUtils.parse(publicCertPem);
      if (x509 == null) {
        privateJwk = generateJWK();
        return privateJwk;
      }
      sha1Thumbprint = Optional.ofNullable(computeSHA1Thumbprint(x509))
          .orElse(new Base64URL(UUID.randomUUID().toString()));
      Base64URL x5tS256 = Optional.ofNullable(computeSHA256Thumbprint(x509))
          .orElse(new Base64URL(UUID.randomUUID().toString()));
      RSAPublicKey publicKey = JWK.parse(x509).toRSAKey().toRSAPublicKey();
      RSAPrivateKey privateKey = JWK.parseFromPEMEncodedObjects(privateKeyPem).toRSAKey().toRSAPrivateKey();
      Base64URL.encode(x509.getEncoded());
      privateJwk = new RSAKey.Builder(publicKey)
          .privateKey(privateKey)
          .keyID(sha1Thumbprint.toString())
          .x509CertSHA256Thumbprint(x5tS256)
          .x509CertChain(List.of(Base64URL.encode(x509.getEncoded())))
          .keyUse(com.nimbusds.jose.jwk.KeyUse.SIGNATURE)
          .algorithm(JWSAlgorithm.RS256)
          .build();
    } catch (CertificateEncodingException | JOSEException e) {
      throw new IllegalStateException(e);
    }
    return privateJwk;
  }

  private LogoutSuccessHandler oidcLogoutSuccessHandler() {
    OidcClientInitiatedLogoutSuccessHandler oidcLogoutSuccessHandler =
        new OidcClientInitiatedLogoutSuccessHandler(this.clientRegistrationRepository);
    // After OIDC logout, the IdP redirects back here; we then show our local logout page
    oidcLogoutSuccessHandler.setPostLogoutRedirectUri(appUrl + "/logout-success");
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

  private final Function<ClientRegistration, JWK> jwkResolver = (clientRegistration) -> {
    if (clientRegistration.getClientAuthenticationMethod().equals(ClientAuthenticationMethod.PRIVATE_KEY_JWT)) {
      return buildJwk();
    }
    return null;
  };

  private JWK generateJWK() {
    try {
      Security.addProvider(new BouncyCastleProvider());
      // Generate EC P-256 key pair
      KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", "BC");
      kpg.initialize(new ECGenParameterSpec("P-256"));
      KeyPair keyPair = kpg.generateKeyPair();
      ECPublicKey ecPublicKey = (ECPublicKey) keyPair.getPublic();
      ECPrivateKey ecPrivateKey = (ECPrivateKey) keyPair.getPrivate();

      // Build self-signed X.509 certificate (valid 10 years)
      String kid = UUID.randomUUID().toString();
      X500Name subject = new X500Name("CN=" + kid);
      Instant now = Instant.now();
      X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
          subject,
          BigInteger.valueOf(System.currentTimeMillis()),
          Date.from(now),
          Date.from(now.plus(30, ChronoUnit.DAYS)),
          subject,
          ecPublicKey
      );
      ContentSigner signer = new JcaContentSignerBuilder("SHA256withECDSA")
          .setProvider("BC")
          .build(ecPrivateKey);
      X509Certificate cert = new JcaX509CertificateConverter()
          .setProvider("BC")
          .getCertificate(certBuilder.build(signer));

      sha1Thumbprint = Optional.ofNullable(computeSHA1Thumbprint(cert))
          .orElse(new Base64URL(kid));
      Base64URL x5tS256 = Optional.ofNullable(computeSHA256Thumbprint(cert))
          .orElse(new Base64URL(kid));

      return new ECKey.Builder(Curve.P_256, ecPublicKey)
          .privateKey(ecPrivateKey)
          .keyID(sha1Thumbprint.toString())
          .keyUse(KeyUse.SIGNATURE)
          .algorithm(JWSAlgorithm.ES256)
          .x509CertSHA256Thumbprint(x5tS256)
          .x509CertChain(List.of(Base64URL.encode(cert.getEncoded())))
          .build();
    } catch (NoSuchAlgorithmException | java.security.InvalidAlgorithmParameterException
             | java.security.NoSuchProviderException
             | OperatorCreationException
             | java.security.cert.CertificateException e) {
      throw new IllegalStateException("Failed to generate ES256 JWK", e);
    }
  }

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
