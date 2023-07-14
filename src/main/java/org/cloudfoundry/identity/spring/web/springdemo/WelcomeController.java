package org.cloudfoundry.identity.spring.web.springdemo;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Controller
public class WelcomeController {

  // inject via application.properties
  @Value("${welcome.message}")
  private String message;


  @GetMapping("/")
  public void main(HttpServletResponse response) throws IOException {
    response.sendRedirect("/index");
  }

  @GetMapping("/index")
  public String home() {
    return "index"; //view
  }

  @GetMapping("/secured")
  public String authenticated(@RegisteredOAuth2AuthorizedClient()
  OAuth2AuthorizedClient authorizedClient, OAuth2AuthenticationToken oauthAuth, Model model) {
    OidcUser user = (OidcUser) oauthAuth.getPrincipal();
    String name = user.getClaim("given_name");
    if (name == null)
      name = user.getClaim("email");
    model.addAttribute("message", message);
    model.addAttribute("name", name);
    model.addAttribute("aud", user.getClaim("aud"));

    return "secured_welcome"; //view
  }

  @GetMapping("/error")
  public String error(Model model) {
    model.addAttribute("message", message);
    return "error"; //view
  }
}