package org.cloudfoundry.identity.spring.web.springdemo;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jose.util.X509CertUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.converter.FormHttpMessageConverter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.client.endpoint.DefaultAuthorizationCodeTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.NimbusJwtClientAuthenticationParametersConverter;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequestEntityConverter;
import org.springframework.security.oauth2.client.endpoint.OAuth2ClientCredentialsGrantRequest;
import org.springframework.security.oauth2.client.http.OAuth2ErrorResponseErrorHandler;
import org.springframework.security.oauth2.client.oidc.web.logout.OidcClientInitiatedLogoutSuccessHandler;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.http.converter.OAuth2AccessTokenResponseHttpMessageConverter;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.web.client.RestTemplate;

import java.net.URI;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.Optional;
import java.util.UUID;
import java.util.function.Function;

@Configuration
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

  @Autowired
  private ClientRegistrationRepository clientRegistrationRepository;

  @Value("${appconfig.appurl}")
  private String appUrl;

  @Value("${appconfig.private-key}")
  private String privateKeyPem;

  @Value("${appconfig.certificate}")
  private String publicCertPem;

  private JWK privateJwk;

  @Override
  public void configure(HttpSecurity http) throws Exception {
    //DefaultAuthorizationCodeTokenResponseClient defaultAuthorizationCodeTokenResponseClient = new DefaultAuthorizationCodeTokenResponseClient();
    //RestTemplate restTemplate = new RestTemplate();
    //defaultAuthorizationCodeTokenResponseClient.setRestOperations(restTemplate);
    Security.addProvider(new BouncyCastleProvider());

    http.
        csrf().disable().
        antMatcher("/**").
        authorizeRequests().
        antMatchers("/secured/**").authenticated().
        anyRequest().permitAll().
        and().
        logout(logout -> logout.logoutSuccessHandler(oidcLogoutSuccessHandler())).
        //oauth2Client(oauth2 -> oauth2.authorizationCodeGrant(codeGrant -> codeGrant.accessTokenResponseClient(accessTokenResponseClient()))).
        oauth2Login().
        tokenEndpoint().
        accessTokenResponseClient(accessTokenResponseClient());

  }

  private LogoutSuccessHandler oidcLogoutSuccessHandler() {
    OidcClientInitiatedLogoutSuccessHandler oidcLogoutSuccessHandler =
        new OidcClientInitiatedLogoutSuccessHandler(
            this.clientRegistrationRepository);

    oidcLogoutSuccessHandler.setPostLogoutRedirectUri(
        URI.create(appUrl));

    return oidcLogoutSuccessHandler;
  }

  private DefaultAuthorizationCodeTokenResponseClient accessTokenResponseClient() {
    RestTemplate restTemplate = new RestTemplate();
    restTemplate.getMessageConverters().addAll(0,
        Arrays.asList(new FormHttpMessageConverter(), new OAuth2AccessTokenResponseHttpMessageConverter()));
    restTemplate.setErrorHandler(new OAuth2ErrorResponseErrorHandler());
    OAuth2AuthorizationCodeGrantRequestEntityConverter requestEntityConverter = new OAuth2AuthorizationCodeGrantRequestEntityConverter();

    NimbusJwtClientAuthenticationParametersConverter<OAuth2ClientCredentialsGrantRequest> converter =
        new NimbusJwtClientAuthenticationParametersConverter<>(jwkResolver);
    /**
     * This client_assertion change is needed only for Azure AD
     */
    converter.setJwtClientAssertionCustomizer((context) -> {
      context.getHeaders().header("x5t", privateJwk.getX509CertThumbprint().toString());
    });
    requestEntityConverter.addParametersConverter((NimbusJwtClientAuthenticationParametersConverter) converter);
    /**
     * Other OIDC providers simply rely on kid
    requestEntityConverter.addParametersConverter(new NimbusJwtClientAuthenticationParametersConverter<>(jwkResolver);
    */

    DefaultAuthorizationCodeTokenResponseClient tokenResponseClient = new DefaultAuthorizationCodeTokenResponseClient();
    tokenResponseClient.setRestOperations(restTemplate);
    tokenResponseClient.setRequestEntityConverter(requestEntityConverter);
    return tokenResponseClient;
  }

  private Function<ClientRegistration, JWK> jwkResolver = (clientRegistration) -> {
    if (clientRegistration.getClientAuthenticationMethod().equals(ClientAuthenticationMethod.PRIVATE_KEY_JWT)) {
      if (privateJwk != null) {
        return privateJwk;
      }
      RSAPublicKey publicKey = null;
      RSAPrivateKey privateKey = null;
      Base64URL x5t;
      try {
        X509Certificate x509 = X509CertUtils.parse(publicCertPem);
        x5t = Optional.ofNullable(computeSHA1Thumbprint(x509)).orElse(new Base64URL(UUID.randomUUID().toString()));
        publicKey = JWK.parse(x509).toRSAKey().toRSAPublicKey();
        privateKey = JWK.parseFromPEMEncodedObjects(privateKeyPem).toRSAKey().toRSAPrivateKey();
      } catch (JOSEException e) {
        throw new RuntimeException(e);
      }
      privateJwk = new RSAKey.Builder(publicKey).privateKey(privateKey).keyID(x5t.toString()).x509CertThumbprint(x5t).build();
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
      MessageDigest sha256 = MessageDigest.getInstance("SHA-1");
      return Base64URL.encode(sha256.digest(derEncodedCert));
    } catch (NoSuchAlgorithmException | CertificateEncodingException e) {
      return null;
    }
  }
}
