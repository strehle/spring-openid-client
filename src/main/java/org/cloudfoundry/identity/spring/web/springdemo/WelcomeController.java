package org.cloudfoundry.identity.spring.web.springdemo;

import net.minidev.json.JSONObject;
import net.minidev.json.parser.JSONParser;
import net.minidev.json.parser.ParseException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Collections;

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
    model.addAttribute("refresh", authorizedClient.getRefreshToken().getTokenValue());
    model.addAttribute("client_id", authorizedClient.getClientRegistration().getClientId());
    model.addAttribute("token_url", authorizedClient.getClientRegistration().getProviderDetails().getTokenUri());

    return "secured_welcome"; //view
  }

  @GetMapping("/error")
  public String error(Model model) {
    model.addAttribute("message", message);
    return "error"; //view
  }

  @PostMapping("/refresh")
  public String refresh(@RequestParam String refresh, @RequestParam String client_id, @RequestParam String token_url,
      HttpServletRequest request, HttpServletResponse response, Model model) throws IOException, ParseException {

    RestTemplate template = new RestTemplate();

    HttpHeaders headers = new HttpHeaders();
    headers.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON));
    headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
    MultiValueMap<String, Object> body = new LinkedMultiValueMap<>();
    body.add("client_id", client_id);
    body.add("refresh_token", refresh);
    body.add("grant_type", "refresh_token");
    HttpEntity<MultiValueMap<String, Object>> entity = new HttpEntity<>(body, headers);

    ResponseEntity webResponse;
    try {
      webResponse =template.exchange(token_url, HttpMethod.POST, entity, String.class);
      JSONObject object = (JSONObject) new JSONParser().parse((String)webResponse.getBody());
      model.addAttribute("message", "Received refresh token");
      model.addAttribute("name", refresh);
      model.addAttribute("client_id",client_id);
      model.addAttribute("token_url", token_url);
      model.addAttribute("refresh", object.getAsString("refresh_token"));
    } catch (HttpClientErrorException e) {
      e.printStackTrace();
      model.addAttribute("message", e.getStatusCode().getReasonPhrase() + " " + e.getMessage());
      return "error";
    }
    return "secured_welcome"; //view
  }
}