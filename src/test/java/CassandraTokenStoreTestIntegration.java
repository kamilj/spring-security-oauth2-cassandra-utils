import com.datastax.driver.core.Cluster;
import com.datastax.driver.core.Session;
import coop.digi.sdis.services.security.util.CassandraTokenStore;
import net.montoma.sdis.services.commons.db.cassandra.CassandraProperties;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit4.SpringRunner;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.InetSocketAddress;
import java.util.Collection;

import static org.junit.Assert.assertEquals;

@RunWith(SpringRunner.class)
@ActiveProfiles("test")
@SpringBootTest
public class CassandraTokenStoreTestIntegration extends TokenStoreBaseTests {

    private Logger LOG = LoggerFactory.getLogger(CassandraTokenStoreTestIntegration.class);
    private String testKeyspace = "oauth_test";

    private Cluster cluster;
    private Session session;

    @Autowired
    private CassandraProperties cassandraProperties;

    private CassandraTokenStore tokenStore;

    @Override
    public CassandraTokenStore getTokenStore() {
        return tokenStore;
    }

    @Before
    public void setUp() throws Exception {
        // create db if not exists
        if (cluster == null || cluster.isClosed()) {
            cluster = getCluster(cassandraProperties);
            setUpKeyspaceAndTables(cluster);
            session = cluster.connect(testKeyspace);

            tokenStore = new CassandraTokenStore(session);
        }
    }

    @Test
    public void testFindAccessTokensByUserName() {
        OAuth2Authentication expectedAuthentication = new OAuth2Authentication(RequestTokenFactory.createOAuth2Request("id", false), new TestAuthentication("test2", false));
        OAuth2AccessToken expectedOAuth2AccessToken = new DefaultOAuth2AccessToken("testToken");
        getTokenStore().storeAccessToken(expectedOAuth2AccessToken, expectedAuthentication);

        Collection<OAuth2AccessToken> actualOAuth2AccessTokens = getTokenStore().findTokensByUserName("test2");
        assertEquals(1, actualOAuth2AccessTokens.size());
    }

    private Cluster getCluster(CassandraProperties cp) {
        return Cluster.builder().addContactPointsWithPorts(
                new InetSocketAddress[]{
                        new InetSocketAddress(
                                cp.getHost(),
                                cp.getPort())
                }
        ).build();
    }

    private void setUpKeyspaceAndTables(Cluster cluster) throws IOException {
        Session session = cluster.connect();
        String[] schemaCommands = getSchema("/oauth_test.cql").split(";");

        for (int i = 0; i < schemaCommands.length - 1; ++i) {

	    String cqlCommand = schemaCommands[i] + ";";

            if (LOG.isDebugEnabled()) {
                LOG.debug("Executing CQL command: " + cqlCommand);
            }
            session.execute(cqlCommand);

        }
        session.close();
    }

    private String getSchema(String filename) throws IOException {
        InputStream is = getClass().getResourceAsStream(filename);
        BufferedReader buf = new BufferedReader(new InputStreamReader(is));

        String line = buf.readLine();
        StringBuilder sb = new StringBuilder();

        while(line != null){
            sb.append(line).append("\n");
            line = buf.readLine();
        }

        String fileAsString = sb.toString();
        return fileAsString;
    }

    // commented out as very heavy
//    @After
//    public void tearDown() throws Exception {
//        session.close();
//        cluster.close();
//    }
}
