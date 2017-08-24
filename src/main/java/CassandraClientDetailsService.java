import com.datastax.driver.core.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.provider.*;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.util.Assert;
import org.springframework.util.ClassUtils;
import org.springframework.util.StringUtils;

import java.util.*;

public class CassandraClientDetailsService implements ClientDetailsService, ClientRegistrationService {

    private static final Logger LOG = LoggerFactory.getLogger(CassandraClientDetailsService.class);

    private static final String CLIENT_FIELDS_FOR_UPDATE = "resource_ids, scope, "
            + "authorized_grant_types, web_server_redirect_uri, authorities, access_token_validity, "
            + "refresh_token_validity, additional_information, autoapprove";

    private static final String CLIENT_FIELDS = "client_secret, " + CLIENT_FIELDS_FOR_UPDATE;

    private static final String BASE_FIND_STATEMENT = "select client_id, " + CLIENT_FIELDS
            + " from oauth_client_details";

    private static final String DEFAULT_FIND_STATEMENT = BASE_FIND_STATEMENT;

    private static final String DEFAULT_SELECT_STATEMENT = BASE_FIND_STATEMENT + " where client_id = ?";

    private static final String DEFAULT_INSERT_STATEMENT = "insert into oauth_client_details (" + CLIENT_FIELDS
            + ", client_id) values (?,?,?,?,?,?,?,?,?,?,?) if not exists";

    private static final String DEFAULT_UPDATE_STATEMENT = "update oauth_client_details " + "set "
            + CLIENT_FIELDS_FOR_UPDATE.replaceAll(", ", "=?, ") + "=? where client_id = ? if exists";

    private static final String DEFAULT_UPDATE_SECRET_STATEMENT = "update oauth_client_details "
            + "set client_secret = ? where client_id = ? if exists";

    private static final String DEFAULT_DELETE_STATEMENT = "delete from oauth_client_details where client_id = ? if exists";


    private String deleteClientDetailsCql = DEFAULT_DELETE_STATEMENT;

    private String findClientDetailsCql = DEFAULT_FIND_STATEMENT;

    private String updateClientDetailsCql = DEFAULT_UPDATE_STATEMENT;

    private String updateClientSecretCql = DEFAULT_UPDATE_SECRET_STATEMENT;

    private String insertClientDetailsCql = DEFAULT_INSERT_STATEMENT;

    private String selectClientDetailsCql = DEFAULT_SELECT_STATEMENT;

    private PasswordEncoder passwordEncoder = NoOpPasswordEncoder.getInstance();

    private Session session;
    private JsonMapper mapper = createJsonMapper();

    private Map<String, PreparedStatement> preparedStatementMap;

    public CassandraClientDetailsService(Session session){
        Assert.notNull(session, "Cassandra session should not be null value.");
        this.session = session;

        prepareStatements();
    }

    public void prepareStatements(){
        preparedStatementMap = new HashMap<>(13);
        preparedStatementMap.put("deleteClientDetailsCql", session.prepare(deleteClientDetailsCql));
        preparedStatementMap.put("findClientDetailsCql", session.prepare(findClientDetailsCql));
        preparedStatementMap.put("updateClientDetailsCql", session.prepare(updateClientDetailsCql));
        preparedStatementMap.put("updateClientSecretCql", session.prepare(updateClientSecretCql));
        preparedStatementMap.put("insertClientDetailsCql", session.prepare(insertClientDetailsCql));
        preparedStatementMap.put("selectClientDetailsCql", session.prepare(selectClientDetailsCql));
    }

    /**
     * @param passwordEncoder the password encoder to set
     */
    public void setPasswordEncoder(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public ClientDetails loadClientByClientId(String clientId) throws ClientRegistrationException {
        Collection<ClientDetails> details;

        BoundStatement bs = new BoundStatement(preparedStatementMap.get("selectClientDetailsCql"));
        bs.bind(clientId);
        ResultSet rs = session.execute(bs);

        details = getClientDetailsFromResultSet(rs);
        if (details.isEmpty()) {
            throw new NoSuchClientException("No client with requested id: " + clientId);
        }

        return details.iterator().next();
    }

    @Override
    public void addClientDetails(ClientDetails clientDetails) throws ClientAlreadyExistsException {
        BoundStatement bs = new BoundStatement(preparedStatementMap.get("insertClientDetailsCql"));
        bs.bind(getFields(clientDetails));
        ResultSet rs = session.execute(bs);

        if (!rs.wasApplied()) {
            throw new ClientAlreadyExistsException("Client already exists: " + clientDetails.getClientId());
        }
    }

    @Override
    public void updateClientDetails(ClientDetails clientDetails) throws NoSuchClientException {
        BoundStatement bs = new BoundStatement(preparedStatementMap.get("updateClientDetailsCql"));
        bs.bind(getFieldsForUpdate(clientDetails));
        ResultSet rs = session.execute(bs);

        if (!rs.wasApplied()) {
            throw new NoSuchClientException("No client found with id = " + clientDetails.getClientId());
        }
    }

    @Override
    public void updateClientSecret(String clientId, String secret) throws NoSuchClientException {
        BoundStatement bs = new BoundStatement(preparedStatementMap.get("updateClientSecretCql"));
        bs.bind(passwordEncoder.encode(secret), clientId);
        ResultSet rs = session.execute(bs);

        if (!rs.wasApplied()) {
            throw new NoSuchClientException("No client found with id = " + clientId);
        }
    }

    @Override
    public void removeClientDetails(String clientId) throws NoSuchClientException {
        BoundStatement bs = new BoundStatement(preparedStatementMap.get("deleteClientDetailsCql"));
        bs.bind(clientId);
        ResultSet rs = session.execute(bs);

        if (!rs.wasApplied()) {
            throw new NoSuchClientException("No client found with id = " + clientId);
        }
    }

    @Override
    public List<ClientDetails> listClientDetails() {
        BoundStatement bs = new BoundStatement(preparedStatementMap.get("findClientDetailsCql"));
        ResultSet rs = session.execute(bs);

        List<ClientDetails> details = getClientDetailsFromResultSet(rs);
        return details;
    }

    private Object[] getFields(ClientDetails clientDetails) {
        Object[] fieldsForUpdate = getFieldsForUpdate(clientDetails);
        Object[] fields = new Object[fieldsForUpdate.length + 1];
        System.arraycopy(fieldsForUpdate, 0, fields, 1, fieldsForUpdate.length);
        fields[0] = clientDetails.getClientSecret() != null ? passwordEncoder.encode(clientDetails.getClientSecret())
                : null;
        return fields;
    }

    private Object[] getFieldsForUpdate(ClientDetails clientDetails) {
        String json = null;
        try {
            json = mapper.write(clientDetails.getAdditionalInformation());
        }
        catch (Exception e) {
            if (LOG.isWarnEnabled()) {
                LOG.warn("Could not serialize additional information: " + clientDetails, e);
            }
        }
        return new Object[] {
                clientDetails.getResourceIds() != null ? StringUtils.collectionToCommaDelimitedString(clientDetails
                        .getResourceIds()) : null,
                clientDetails.getScope() != null ? StringUtils.collectionToCommaDelimitedString(clientDetails
                        .getScope()) : null,
                clientDetails.getAuthorizedGrantTypes() != null ? StringUtils
                        .collectionToCommaDelimitedString(clientDetails.getAuthorizedGrantTypes()) : null,
                clientDetails.getRegisteredRedirectUri() != null ? StringUtils
                        .collectionToCommaDelimitedString(clientDetails.getRegisteredRedirectUri()) : null,
                clientDetails.getAuthorities() != null ? StringUtils.collectionToCommaDelimitedString(clientDetails
                        .getAuthorities()) : null, clientDetails.getAccessTokenValiditySeconds(),
                clientDetails.getRefreshTokenValiditySeconds(), json, getAutoApproveScopes(clientDetails),
                clientDetails.getClientId() };
    }

    private String getAutoApproveScopes(ClientDetails clientDetails) {
        if (clientDetails.isAutoApprove("true")) {
            return "true"; // all scopes autoapproved
        }
        Set<String> scopes = new HashSet<String>();
        for (String scope : clientDetails.getScope()) {
            if (clientDetails.isAutoApprove(scope)) {
                scopes.add(scope);
            }
        }
        return StringUtils.collectionToCommaDelimitedString(scopes);
    }

    public void setSelectClientDetailsCql(String selectClientDetailsCql) {
        this.selectClientDetailsCql = selectClientDetailsCql;
        preparedStatementMap.put("selectClientDetailsCql", session.prepare(selectClientDetailsCql));
    }

    public void setDeleteClientDetailsCql(String deleteClientDetailsCql) {
        this.deleteClientDetailsCql = deleteClientDetailsCql;
        preparedStatementMap.put("deleteClientDetailsCql", session.prepare(deleteClientDetailsCql));
    }

    public void setUpdateClientDetailsCql(String updateClientDetailsCql) {
        this.updateClientDetailsCql = updateClientDetailsCql;
        preparedStatementMap.put("updateClientDetailsCql", session.prepare(updateClientDetailsCql));
    }

    public void setUpdateClientSecretCql(String updateClientSecretCql) {
        this.updateClientSecretCql = updateClientSecretCql;
        preparedStatementMap.put("updateClientSecretCql", session.prepare(updateClientSecretCql));
    }

    public void setInsertClientDetailsCql(String insertClientDetailsCql) {
        this.insertClientDetailsCql = insertClientDetailsCql;
        preparedStatementMap.put("insertClientDetailsCql", session.prepare(insertClientDetailsCql));
    }

    public void setFindClientDetailsCql(String findClientDetailsCql) {
        this.findClientDetailsCql = findClientDetailsCql;
        preparedStatementMap.put("findClientDetailsCql", session.prepare(findClientDetailsCql));
    }

    private List<ClientDetails> getClientDetailsFromResultSet(ResultSet rs) {

        if (rs.isExhausted()) {
            return Collections.EMPTY_LIST;
        }

        List<ClientDetails> result = new ArrayList<>();
        JsonMapper mapper = createJsonMapper();

        for (Row row: rs) {
            BaseClientDetails details = new BaseClientDetails(
                    row.getString(0),
                    row.getString(2),
                    row.getString(3),
                    row.getString(4),
                    row.getString(6),
                    row.getString(5)
            );

            details.setClientSecret(row.getString(1));
            if (row.getObject(7) != null) {
                details.setAccessTokenValiditySeconds(row.getInt(7));
            }
            if (row.getObject(8) != null) {
                details.setRefreshTokenValiditySeconds(row.getInt(8));
            }
            String json = row.getString(9);
            if (json != null) {
                try {
                    @SuppressWarnings("unchecked")
                    Map<String, Object> additionalInformation = mapper.read(json, Map.class);
                    details.setAdditionalInformation(additionalInformation);
                } catch (Exception e) {
                    if (LOG.isWarnEnabled()) {
                        LOG.warn("Could not decode JSON for additional information: " + details, e);
                    }
                }
            }

            String scopes = row.getString(10);
            if (scopes != null) {
                details.setAutoApproveScopes(StringUtils.commaDelimitedListToSet(scopes));
            }
            result.add(details);
        }

        Collections.sort(result, Comparator.comparing(ClientDetails::getClientId));
        return result;
    }

    interface JsonMapper {
        String write(Object input) throws Exception;

        <T> T read(String input, Class<T> type) throws Exception;
    }

    private static JsonMapper createJsonMapper() {
        if (ClassUtils.isPresent("org.codehaus.jackson.map.ObjectMapper", null)) {
            return new JacksonMapper();
        }
        else if (ClassUtils.isPresent("com.fasterxml.jackson.databind.ObjectMapper", null)) {
            return new Jackson2Mapper();
        }
        return new NotSupportedJsonMapper();
    }

    private static class JacksonMapper implements JsonMapper {
        private org.codehaus.jackson.map.ObjectMapper mapper = new org.codehaus.jackson.map.ObjectMapper();

        @Override
        public String write(Object input) throws Exception {
            return mapper.writeValueAsString(input);
        }

        @Override
        public <T> T read(String input, Class<T> type) throws Exception {
            return mapper.readValue(input, type);
        }
    }

    private static class Jackson2Mapper implements JsonMapper {
        private com.fasterxml.jackson.databind.ObjectMapper mapper = new com.fasterxml.jackson.databind.ObjectMapper();

        @Override
        public String write(Object input) throws Exception {
            return mapper.writeValueAsString(input);
        }

        @Override
        public <T> T read(String input, Class<T> type) throws Exception {
            return mapper.readValue(input, type);
        }
    }

    private static class NotSupportedJsonMapper implements JsonMapper {
        @Override
        public String write(Object input) throws Exception {
            throw new UnsupportedOperationException(
                    "Neither Jackson 1 nor 2 is available so JSON conversion cannot be done");
        }

        @Override
        public <T> T read(String input, Class<T> type) throws Exception {
            throw new UnsupportedOperationException(
                    "Neither Jackson 1 nor 2 is available so JSON conversion cannot be done");
        }
    }

}
