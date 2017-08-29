package coop.digi.sdis.services.security.util;

import coop.digi.sdis.services.security.domain.DomainUser;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.common.exceptions.InvalidGrantException;
import org.springframework.security.oauth2.provider.*;
import org.springframework.security.oauth2.provider.token.AbstractTokenGranter;
import org.springframework.security.oauth2.provider.token.AuthorizationServerTokenServices;

import java.util.*;

/**
 * Implementation of Token Granter.
 * The flow is:
 * 1. User connects to /oauth/token endpoint with fields:
 *      grant_type="service"
 *      service_id=UUID
 *      service_name=String
 * Token is authenticated with fake user, containing userId = serviceId, and userName = serviceName.
 * Later requests can be done with that token, making sure they are run from some service, not from user.
 */
public class ServiceTokenGranter extends AbstractTokenGranter {

    private static final String GRANT_TYPE = "service";

    public ServiceTokenGranter(AuthorizationServerTokenServices tokenServices, ClientDetailsService clientDetailsService, OAuth2RequestFactory requestFactory) {
        this(tokenServices, clientDetailsService, requestFactory, GRANT_TYPE);
    }

    protected ServiceTokenGranter(AuthorizationServerTokenServices tokenServices,
                                                ClientDetailsService clientDetailsService, OAuth2RequestFactory requestFactory, String grantType) {
        super(tokenServices, clientDetailsService, requestFactory, grantType);
    }

    @Override
    protected OAuth2Authentication getOAuth2Authentication(ClientDetails client, TokenRequest tokenRequest) {

        Map<String, String> parameters = new LinkedHashMap<String, String>(tokenRequest.getRequestParameters());
        String serviceId = parameters.get("service_id");
        String serviceName = parameters.get("service_name");

        UUID serviceUUID;
        try {
            serviceUUID = UUID.fromString(serviceId);
        } catch (IllegalArgumentException e) {
            throw new InvalidGrantException(e.getMessage());
        }

        if (serviceName == null || serviceName.trim().isEmpty()) {
            throw new InvalidGrantException("Service name can't be empty");
        }

        serviceName = serviceName.trim();
        DomainUser principal = new DomainUser(serviceUUID, serviceName, null, true, true);
        principal.setService(true);

        Set<GrantedAuthority> roles = new HashSet<>();
        roles.add(new SimpleGrantedAuthority("ROLE_SERVICE"));

        Authentication serviceAuth = new AnonymousAuthenticationToken("service", principal, roles);
        ((AbstractAuthenticationToken)serviceAuth).setDetails(parameters);

        OAuth2Request storedOAuth2Request = getRequestFactory().createOAuth2Request(client, tokenRequest);
        return new OAuth2Authentication(storedOAuth2Request, serviceAuth);
    }
}
