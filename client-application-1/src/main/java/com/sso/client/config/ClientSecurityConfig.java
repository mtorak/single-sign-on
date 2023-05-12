package com.sso.client.config;

import com.sun.xml.bind.v2.TODO;
import java.util.ArrayList;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.ldap.core.LdapTemplate;
import org.springframework.ldap.core.support.LdapContextSource;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2RestOperations;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.resource.OAuth2ProtectedResourceDetails;
import org.springframework.security.oauth2.client.token.grant.client.ClientCredentialsResourceDetails;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableOAuth2Client;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;

@EnableOAuth2Client
@Configuration
public class ClientSecurityConfig extends WebSecurityConfigurerAdapter {

  @Value("${ldap.partitionSuffix}")
  private String baseDn;

  @Value("${ldap.url}")
  private String ldapUrl;

  @Value("${auth.server.exitUrl}")
  private String exitUrl;

  @Autowired
  private ClientRegistrationRepository clientRegistrationRepository;

  @Bean
  public OAuth2RestOperations restTemplate(OAuth2ClientContext oauth2ClientContext) {
    return new OAuth2RestTemplate(resource(), oauth2ClientContext);
  }

  @Bean
  protected OAuth2ProtectedResourceDetails resource() {
    ClientRegistration clientRegistration = clientRegistrationRepository.findByRegistrationId("custom");

    ClientCredentialsResourceDetails resource = new ClientCredentialsResourceDetails();
    resource.setAccessTokenUri(clientRegistration.getProviderDetails().getTokenUri());
    resource.setClientId(clientRegistration.getClientId());
    resource.setClientSecret(clientRegistration.getClientSecret());

    List<String> scopes = new ArrayList<>(2);
    scopes.add("write");
    scopes.add("read");
    resource.setScope(scopes);

    return resource;
  }

  @Override
  public void configure(HttpSecurity http) throws Exception {
    http.authorizeRequests()
        .antMatchers("/clogin", "/assets/**", "/js/**", "/fonts/**")
        .permitAll()
        .and()
        .authorizeRequests()
        .anyRequest()
        .authenticated()
        .and()
        .oauth2Login()
        .and().logout().logoutSuccessUrl(exitUrl).invalidateHttpSession(true)
        .deleteCookies("JSESSIONID");

    http.oauth2Login()
        .userInfoEndpoint()
        .userService(oauthUserService());
  }

  @Bean
  public OAuth2UserService oauthUserService() {
    return new MyCustomOAuth2UserService();
  }

  @Bean
  public LdapContextSource contextSource() {
    LdapContextSource contextSource = new LdapContextSource();

    contextSource.setUrl(ldapUrl);
    contextSource.setBase(baseDn);
    return contextSource;
  }

  @Bean
  public LdapTemplate ldapTemplate() {
    return new LdapTemplate(contextSource());
  }

  class MyCustomOAuth2UserService implements OAuth2UserService<OAuth2UserRequest, OAuth2User> {

    @Override
    public OAuth2User loadUser(OAuth2UserRequest oAuth2UserRequest) throws OAuth2AuthenticationException {
      // this will be null if the OAuth2UserRequest is not from an authenticated user
      // otherwise, it would contain the current user's principle which you can use to check if the OAuth request should be handled or not
      Authentication currentAuth = SecurityContextHolder.getContext().getAuthentication();

      // for example:
      // if(currentAuth == null)
      //     throw new OAuth2AuthenticationException(OAuth2ErrorCodes.ACCESS_DENIED);

      // Use the default service to load the user
      DefaultOAuth2UserService defaultService = new DefaultOAuth2UserService();
      OAuth2User defaultOAuthUser = defaultService.loadUser(oAuth2UserRequest);

      //TODO
      // here you might have extra logic to map the defaultOAuthUser's info to the existing user
      // and if you're implementing a custom OAuth2User you should also connect them here and return the custom OAuth2User

      return defaultOAuthUser;
    }
  }

}
