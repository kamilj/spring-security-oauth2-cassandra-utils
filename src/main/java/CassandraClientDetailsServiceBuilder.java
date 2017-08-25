import com.datastax.driver.core.Session;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.config.annotation.builders.ClientDetailsServiceBuilder;
import org.springframework.security.oauth2.provider.ClientAlreadyExistsException;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.util.Assert;

import java.util.HashSet;
import java.util.Set;

public class CassandraClientDetailsServiceBuilder extends ClientDetailsServiceBuilder<CassandraClientDetailsServiceBuilder> {

    private Logger LOG = LoggerFactory.getLogger(CassandraClientDetailsService.class);

    private Session session;
    private Set<ClientDetails> clientDetails = new HashSet<ClientDetails>();

    private PasswordEncoder passwordEncoder; // for writing client secrets

    public CassandraClientDetailsServiceBuilder session(Session session) {
        this.session = session;
        return this;
    }

    public CassandraClientDetailsServiceBuilder passwordEncoder(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
        return this;
    }

    @Override
    protected void addClient(String clientId, ClientDetails value) {
        clientDetails.add(value);
    }

    @Override
    protected ClientDetailsService performBuild() {
        Assert.state(session != null, "You need to provide a Cassandra session");
        CassandraClientDetailsService clientDetailsService = new CassandraClientDetailsService(session);
        if (passwordEncoder != null) {
            // This is used to encode secrets as they are added to the database (if it isn't set then the user has top
            // pass in pre-encoded secrets)
            clientDetailsService.setPasswordEncoder(passwordEncoder);
        }
        for (ClientDetails client : clientDetails) {
            try {
		if (LOG.isDebugEnabled()) {
                    LOG.debug("Add client: " + client);
                }
                clientDetailsService.addClientDetails(client);
            } catch (ClientAlreadyExistsException e) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Client already exists: " + client + e);
                }
            }
        }
        return clientDetailsService;
    }
}
