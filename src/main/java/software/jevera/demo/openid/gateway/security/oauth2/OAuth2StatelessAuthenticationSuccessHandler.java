package software.jevera.demo.openid.gateway.security.oauth2;

import lombok.RequiredArgsConstructor;
import lombok.Value;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.AbstractOAuth2Token;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

import static java.util.Optional.ofNullable;

@Component
@RequiredArgsConstructor
public class OAuth2StatelessAuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private final OAuth2AuthorizedClientService authorizedClientService;

    @Override
    protected void handle(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        OAuth2AuthenticationToken auth = (OAuth2AuthenticationToken) authentication;
        OAuth2User principal = auth.getPrincipal();
        String authorizedClientRegistrationId = auth.getAuthorizedClientRegistrationId();
        OAuth2AuthorizedClient oAuth2AuthorizedClient =
            authorizedClientService.loadAuthorizedClient(authorizedClientRegistrationId, principal.getName());

        ofNullable(oAuth2AuthorizedClient.getAccessToken())
            .map(OAuth2AccessToken::getTokenValue)
            .ifPresent(token -> response.addCookie(createCookie("ACCESS_TOKEN", token)));

        ofNullable(oAuth2AuthorizedClient.getRefreshToken())
            .map(OAuth2RefreshToken::getTokenValue)
            .ifPresent(token -> response.addCookie(createCookie("REFRESH_TOKEN", token)));

        if (principal instanceof OidcUser) {
            OidcUser oidcUser = (OidcUser) principal;
            ofNullable(oidcUser.getIdToken())
                .map(AbstractOAuth2Token::getTokenValue)
                .ifPresent(token -> response.addCookie(createCookie("ID_TOKEN", token)));
        }
        HttpCookieOAuth2AuthorizationRequestRepository.deleteCookies(request, response);
        authorizedClientService.removeAuthorizedClient(authorizedClientRegistrationId, principal.getName());

        super.handle(request, response, authentication);
    }

    private Cookie createCookie(String name, String value) {
        Cookie cookie = new Cookie(name, value);
        cookie.setMaxAge(60);
        cookie.setPath("/");
        return cookie;
    }
}
