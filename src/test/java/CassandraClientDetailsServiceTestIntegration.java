import com.datastax.driver.core.*;
import com.datastax.driver.core.querybuilder.QueryBuilder;
import coop.digi.sdis.services.security.util.CassandraClientDetailsService;
import net.montoma.sdis.services.commons.db.cassandra.CassandraProperties;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.provider.ClientAlreadyExistsException;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.NoSuchClientException;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit4.SpringRunner;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.InetSocketAddress;
import java.util.*;

import static org.junit.Assert.*;

@RunWith(SpringRunner.class)
@ActiveProfiles("test")
@SpringBootTest
public class CassandraClientDetailsServiceTestIntegration {

    private static final String SELECT_CQL = "select client_id, client_secret, resource_ids, scope, authorized_grant_types, web_server_redirect_uri, authorities, access_token_validity, refresh_token_validity from oauth_client_details where client_id=?";

    private static final String INSERT_CQL = "insert into oauth_client_details (client_id, client_secret, resource_ids, scope, authorized_grant_types, web_server_redirect_uri, authorities, access_token_validity, refresh_token_validity, autoapprove) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";

    private static final String CUSTOM_INSERT_CQL = "insert into ClientDetails (appId, appSecret, resourceIds, scope, grantTypes, redirectUrl, authorities) values (?, ?, ?, ?, ?, ?, ?)";

    private Logger LOG = LoggerFactory.getLogger(CassandraTokenStoreTestIntegration.class);
    private String testKeyspace = "oauth_test";

    private Cluster cluster;
    private Session session;

    @Autowired
    private CassandraProperties cassandraProperties;

    private CassandraClientDetailsService service;

    @Before
    public void setUp() throws Exception {
        // create db if not exists
        if (cluster == null || cluster.isClosed()) {
            cluster = getCluster(cassandraProperties);
            setUpKeyspaceAndTables(cluster);
            session = cluster.connect(testKeyspace);

            service = new CassandraClientDetailsService(session);
        }

        // truncate tables
        session.execute(QueryBuilder.truncate("oauth_client_details"));
        session.execute(QueryBuilder.truncate("ClientDetails"));
    }

    @Test(expected = NoSuchClientException.class)
    public void testLoadingClientForNonExistingClientId() {
        service.loadClientByClientId("nonExistingClientId");
    }

    @Test
    public void testLoadingClientIdWithNoDetails() {
        //given
        PreparedStatement preparedStatement = session.prepare(INSERT_CQL);
        BoundStatement bs = preparedStatement.bind("clientIdWithNoDetails", null, null,
                null, null, null, null, null, null, null);
        session.execute(bs);

        // when
        ClientDetails clientDetails = service
                .loadClientByClientId("clientIdWithNoDetails");

        // then
        assertEquals("clientIdWithNoDetails", clientDetails.getClientId());
        assertFalse(clientDetails.isSecretRequired());
        assertNull(clientDetails.getClientSecret());
        assertFalse(clientDetails.isScoped());
        assertEquals(0, clientDetails.getScope().size());
        assertEquals(2, clientDetails.getAuthorizedGrantTypes().size());
        assertNull(clientDetails.getRegisteredRedirectUri());
        assertEquals(0, clientDetails.getAuthorities().size());
        assertEquals(null, clientDetails.getAccessTokenValiditySeconds());
        assertEquals(null, clientDetails.getAccessTokenValiditySeconds());
    }

    @Test
    public void testLoadingClientIdWithAdditionalInformation() {
        // given
        PreparedStatement preparedStatement = session.prepare(INSERT_CQL);
        BoundStatement bs = preparedStatement.bind("clientIdWithAddInfo", null, null,
                null, null, null, null, null, null, null);
        session.execute(bs);

        PreparedStatement preparedStatement1 = session.prepare("update oauth_client_details set additional_information=? where client_id=?");
        BoundStatement bs1 = preparedStatement1.bind("{\"foo\":\"bar\"}", "clientIdWithAddInfo");
        session.execute(bs1);

        // when
        ClientDetails clientDetails = service
                .loadClientByClientId("clientIdWithAddInfo");

        // then
        assertEquals("clientIdWithAddInfo", clientDetails.getClientId());
        assertEquals(Collections.singletonMap("foo", "bar"),
                clientDetails.getAdditionalInformation());
    }

    @Test
    public void testLoadingClientIdWithSingleDetails() {
        // given
        PreparedStatement preparedStatement = session.prepare(INSERT_CQL);
        BoundStatement bs = preparedStatement.bind("clientIdWithSingleDetails",
                "mySecret", "myResource", "myScope", "myAuthorizedGrantType",
                "myRedirectUri", "myAuthority", 100, 200, "true");
        session.execute(bs);

        // when
        ClientDetails clientDetails = service
                .loadClientByClientId("clientIdWithSingleDetails");

        // then
        assertEquals("clientIdWithSingleDetails", clientDetails.getClientId());
        assertTrue(clientDetails.isSecretRequired());
        assertEquals("mySecret", clientDetails.getClientSecret());
        assertTrue(clientDetails.isScoped());
        assertEquals(1, clientDetails.getScope().size());
        assertEquals("myScope", clientDetails.getScope().iterator().next());
        assertEquals(1, clientDetails.getResourceIds().size());
        assertEquals("myResource", clientDetails.getResourceIds().iterator()
                .next());
        assertEquals(1, clientDetails.getAuthorizedGrantTypes().size());
        assertEquals("myAuthorizedGrantType", clientDetails
                .getAuthorizedGrantTypes().iterator().next());
        assertEquals("myRedirectUri", clientDetails.getRegisteredRedirectUri()
                .iterator().next());
        assertEquals(1, clientDetails.getAuthorities().size());
        assertEquals("myAuthority", clientDetails.getAuthorities().iterator()
                .next().getAuthority());
        assertEquals(new Integer(100),
                clientDetails.getAccessTokenValiditySeconds());
        assertEquals(new Integer(200),
                clientDetails.getRefreshTokenValiditySeconds());
    }

    @Test
    public void testLoadingClientIdWithSingleDetailsInCustomTable() {
        // given

        PreparedStatement preparedStatement = session.prepare(CUSTOM_INSERT_CQL);
        BoundStatement bs = preparedStatement.bind("clientIdWithSingleDetails",
                "mySecret", "myResource", "myScope", "myAuthorizedGrantType",
                "myRedirectUri", "myAuthority");
        session.execute(bs);

        CassandraClientDetailsService customService = new CassandraClientDetailsService(
                session);
        customService
                .setSelectClientDetailsCql("select appId, appSecret, resourceIds, scope, "
                        + "grantTypes, redirectUrl, authorities, access_token_validity, refresh_token_validity, additionalInformation, autoApproveScopes from ClientDetails where appId = ?");

        // when
        ClientDetails clientDetails = customService
                .loadClientByClientId("clientIdWithSingleDetails");

        // then
        assertEquals("clientIdWithSingleDetails", clientDetails.getClientId());
        assertTrue(clientDetails.isSecretRequired());
        assertEquals("mySecret", clientDetails.getClientSecret());
        assertTrue(clientDetails.isScoped());
        assertEquals(1, clientDetails.getScope().size());
        assertEquals("myScope", clientDetails.getScope().iterator().next());
        assertEquals(1, clientDetails.getResourceIds().size());
        assertEquals("myResource", clientDetails.getResourceIds().iterator()
                .next());
        assertEquals(1, clientDetails.getAuthorizedGrantTypes().size());
        assertEquals("myAuthorizedGrantType", clientDetails
                .getAuthorizedGrantTypes().iterator().next());
        assertEquals("myRedirectUri", clientDetails.getRegisteredRedirectUri()
                .iterator().next());
        assertEquals(1, clientDetails.getAuthorities().size());
        assertEquals("myAuthority", clientDetails.getAuthorities().iterator()
                .next().getAuthority());
    }

    @Test
    public void testLoadingClientIdWithMultipleDetails() {
        // given
        PreparedStatement preparedStatement = session.prepare(INSERT_CQL);
        BoundStatement bs = preparedStatement.bind("clientIdWithMultipleDetails",
                "mySecret", "myResource1,myResource2", "myScope1,myScope2",
                "myAuthorizedGrantType1,myAuthorizedGrantType2",
                "myRedirectUri1,myRedirectUri2", "myAuthority1,myAuthority2",
                100, 200, "read,write");
        session.execute(bs);

        // when
        ClientDetails clientDetails = service
                .loadClientByClientId("clientIdWithMultipleDetails");

        // then
        assertEquals("clientIdWithMultipleDetails", clientDetails.getClientId());
        assertTrue(clientDetails.isSecretRequired());
        assertEquals("mySecret", clientDetails.getClientSecret());
        assertTrue(clientDetails.isScoped());
        assertEquals(2, clientDetails.getResourceIds().size());
        Iterator<String> resourceIds = clientDetails.getResourceIds()
                .iterator();
        assertEquals("myResource1", resourceIds.next());
        assertEquals("myResource2", resourceIds.next());
        assertEquals(2, clientDetails.getScope().size());
        Iterator<String> scope = clientDetails.getScope().iterator();
        assertEquals("myScope1", scope.next());
        assertEquals("myScope2", scope.next());
        assertEquals(2, clientDetails.getAuthorizedGrantTypes().size());
        Iterator<String> grantTypes = clientDetails.getAuthorizedGrantTypes()
                .iterator();
        assertEquals("myAuthorizedGrantType1", grantTypes.next());
        assertEquals("myAuthorizedGrantType2", grantTypes.next());
        assertEquals(2, clientDetails.getRegisteredRedirectUri().size());
        Iterator<String> redirectUris = clientDetails
                .getRegisteredRedirectUri().iterator();
        assertEquals("myRedirectUri1", redirectUris.next());
        assertEquals("myRedirectUri2", redirectUris.next());
        assertEquals(2, clientDetails.getAuthorities().size());
        Iterator<GrantedAuthority> authorities = clientDetails.getAuthorities()
                .iterator();
        assertEquals("myAuthority1", authorities.next().getAuthority());
        assertEquals("myAuthority2", authorities.next().getAuthority());
        assertEquals(new Integer(100),
                clientDetails.getAccessTokenValiditySeconds());
        assertEquals(new Integer(200),
                clientDetails.getRefreshTokenValiditySeconds());
        assertTrue(clientDetails.isAutoApprove("read"));
    }

    @Test
    public void testAddClientWithNoDetails() {
        // given
        BaseClientDetails clientDetails = new BaseClientDetails();
        clientDetails.setClientId("addedClientIdWithNoDetails");

        // when
        service.addClientDetails(clientDetails);

        // then
        PreparedStatement preparedStatement = session.prepare(SELECT_CQL);
        BoundStatement bs = preparedStatement.bind("addedClientIdWithNoDetails");
        ResultSet rs = session.execute(bs);
        Map<String, Object> map = queryResultSetForMap(rs);

        assertEquals("addedClientIdWithNoDetails", map.get("client_id"));
        assertTrue(map.containsKey("client_secret"));
        assertEquals(null, map.get("client_secret"));
    }

    @Test(expected = ClientAlreadyExistsException.class)
    public void testInsertDuplicateClient() {

        BaseClientDetails clientDetails = new BaseClientDetails();
        clientDetails.setClientId("duplicateClientIdWithNoDetails");

        service.addClientDetails(clientDetails);
        service.addClientDetails(clientDetails);
    }

    @Test
    public void testUpdateClientSecret() {
        // given
        BaseClientDetails clientDetails = new BaseClientDetails();
        clientDetails.setClientId("newClientIdWithNoDetails");

        service.setPasswordEncoder(new PasswordEncoder() {

            public boolean matches(CharSequence rawPassword,
                                   String encodedPassword) {
                return true;
            }

            public String encode(CharSequence rawPassword) {
                return "BAR";
            }
        });

        // when
        service.addClientDetails(clientDetails);
        service.updateClientSecret(clientDetails.getClientId(), "foo");

        // then
        PreparedStatement preparedStatement = session.prepare(SELECT_CQL);
        BoundStatement bs = preparedStatement.bind("newClientIdWithNoDetails");
        ResultSet rs = session.execute(bs);
        Map<String, Object> map = queryResultSetForMap(rs);

        assertEquals("newClientIdWithNoDetails", map.get("client_id"));
        assertTrue(map.containsKey("client_secret"));
        assertEquals("BAR", map.get("client_secret"));
    }



    @Test
    public void testUpdateClientRedirectURI() {
        // given
        BaseClientDetails clientDetails = new BaseClientDetails();
        clientDetails.setClientId("newClientIdWithNoDetails");

        service.addClientDetails(clientDetails);

        String[] redirectURI = { "http://localhost:8080",
                "http://localhost:9090" };
        clientDetails.setRegisteredRedirectUri(new HashSet<String>(Arrays
                .asList(redirectURI)));

        // when
        service.updateClientDetails(clientDetails);

        // then
        PreparedStatement preparedStatement = session.prepare(SELECT_CQL);
        BoundStatement bs = preparedStatement.bind("newClientIdWithNoDetails");
        ResultSet rs = session.execute(bs);
        Map<String, Object> map = queryResultSetForMap(rs);

        assertEquals("newClientIdWithNoDetails", map.get("client_id"));
        assertTrue(map.containsKey("web_server_redirect_uri"));
        assertEquals("http://localhost:8080,http://localhost:9090",
                map.get("web_server_redirect_uri"));
    }

    @Test(expected = NoSuchClientException.class)
    public void testUpdateNonExistentClient() {

        BaseClientDetails clientDetails = new BaseClientDetails();
        clientDetails.setClientId("nosuchClientIdWithNoDetails");

        service.updateClientDetails(clientDetails);
    }

    @Test
    public void testRemoveClient() {
        // given
        BaseClientDetails clientDetails = new BaseClientDetails();
        clientDetails.setClientId("deletedClientIdWithNoDetails");

        // when
        service.addClientDetails(clientDetails);
        service.removeClientDetails(clientDetails.getClientId());

        // then
        PreparedStatement preparedStatement = session.prepare("select count(*) from oauth_client_details where client_id=?");
        BoundStatement bs = preparedStatement.bind("deletedClientIdWithNoDetails");
        ResultSet rs = session.execute(bs);
        assertFalse(rs.isExhausted());
        long count = rs.one().getLong(0);
        assertEquals(0, count);
    }

    @Test(expected = NoSuchClientException.class)
    public void testRemoveNonExistentClient() {

        BaseClientDetails clientDetails = new BaseClientDetails();
        clientDetails.setClientId("nosuchClientIdWithNoDetails");

        service.removeClientDetails(clientDetails.getClientId());
    }

    @Test
    public void testFindClients() {

        BaseClientDetails clientDetails = new BaseClientDetails();
        clientDetails.setClientId("aclient");

        service.addClientDetails(clientDetails);
        int count = service.listClientDetails().size();

        assertEquals(1, count);
    }

    private Map<String, Object> queryResultSetForMap(ResultSet rs) {
        Map<String, Object> map = new HashMap<>();

        if (!rs.isExhausted()) {
            Row row = rs.one();
            ColumnDefinitions columns = rs.getColumnDefinitions();
            columns.iterator().forEachRemaining(column -> {
                map.put(column.getName(), row.getObject(column.getName()));
            });
        }
        return map;
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
            if (LOG.isDebugEnabled()) {
                LOG.info("Executing CQL command: " + schemaCommands[i] +";");
            }
            session.execute(schemaCommands[i] + ";");
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
}
