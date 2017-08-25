package config;

import com.datastax.driver.core.Session;
import coop.digi.sdis.services.security.config.cassandra.CassandraDB;
import coop.digi.sdis.services.security.util.CassandraClientDetailsService;
import coop.digi.sdis.services.security.util.CassandraClientDetailsServiceBuilder;
import coop.digi.sdis.services.security.util.CassandraTokenStore;
import coop.digi.sdis.services.security.util.MyClientDetailsServiceConfigurer;
import net.montoma.sdis.services.commons.db.cassandra.CassandraProperties;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.*;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.config.annotation.builders.ClientDetailsServiceBuilder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.token.TokenStore;

@Configuration
@EnableAuthorizationServer
public class OAuth2AuthorizationConfig extends AuthorizationServerConfigurerAdapter {

    @Autowired
    @Qualifier("authenticationManagerBean")
    private AuthenticationManager authenticationManager;

    @Autowired
    private UserDetailsService userDetailsService;

    @Autowired
    private TokenStore tokenStore;

    @Autowired
    private CassandraProperties myCassandraProperties;

    @Autowired
    private ClientDetailsServiceConfigurer myClientDetailsServiceConfigurer;

    @Autowired
    private CassandraDB cassandraDB;

    @Override
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
        CassandraClientDetailsServiceBuilder builder = new CassandraClientDetailsServiceBuilder();
        builder.session(session())
                .withClient("web_app")
		        .scopes("ui")
		        .authorizedGrantTypes("refresh_token", "password")
                .and().build();
        clients.configure(builder);

    }

    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
        endpoints
                .tokenStore(tokenStore)
                .userDetailsService(userDetailsService)
                .authenticationManager(authenticationManager);
    }

    @Bean
    @Scope(proxyMode = ScopedProxyMode.INTERFACES)
    public Session session() {
        return cassandraDB.getSession(myCassandraProperties.getKeyspace());
    }

    @Bean
    @Scope(proxyMode = ScopedProxyMode.INTERFACES)
    public TokenStore tokenStore() {
            return new CassandraTokenStore(session());
    }

    @Bean
    @Scope(proxyMode = ScopedProxyMode.INTERFACES)
    public ClientDetailsService clientDetailsService() {
        return new CassandraClientDetailsService(session());
    }

    @Bean
    @Scope(proxyMode = ScopedProxyMode.TARGET_CLASS)
    public ClientDetailsServiceConfigurer clientDetailsServiceConfigurer() {
        return new MyClientDetailsServiceConfigurer(new ClientDetailsServiceBuilder());
    }

    @Override
    public void configure(AuthorizationServerSecurityConfigurer oauthServer) throws Exception {
        oauthServer
                .tokenKeyAccess("permitAll()")
                .checkTokenAccess("isAuthenticated()");
    }
}
