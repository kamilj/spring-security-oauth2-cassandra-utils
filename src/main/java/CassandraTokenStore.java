import com.datastax.driver.core.*;
import com.datastax.driver.core.exceptions.CodecNotFoundException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2RefreshToken;
import org.springframework.security.oauth2.common.util.SerializationUtils;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.AuthenticationKeyGenerator;
import org.springframework.security.oauth2.provider.token.DefaultAuthenticationKeyGenerator;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.util.Assert;

import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;
import java.util.stream.Collectors;

/**
 *  Implementation of token services that stores token in a Cassandra database.
 *
 *  @author Fedor Konstantinov
 */
public class CassandraTokenStore implements TokenStore {

    private static final Logger LOG = LoggerFactory.getLogger(CassandraTokenStore.class);

    /** oauth_access_token table */
    private static final String DEFAULT_ACCESS_TOKEN_INSERT_STATEMENT = "insert into oauth_access_token (token_id, auth_token, authentication_id, user_name, client_id, authentication, refresh_token) values (?, ?, ?, ?, ?, ?, ?)";

    private static final String DEFAULT_ACCESS_TOKEN_SELECT_STATEMENT = "select token_id, auth_token from oauth_access_token where token_id = ?";

    private static final String DEFAULT_ACCESS_TOKEN_AUTHENTICATION_SELECT_STATEMENT = "select token_id, authentication from oauth_access_token where token_id = ?";

    private static final String DEFAULT_ACCESS_TOKEN_FROM_AUTHENTICATION_SELECT_STATEMENT = "select token_id, auth_token from oauth_access_token_by_authentication_id where authentication_id = ?";

    private static final String DEFAULT_ACCESS_TOKENS_FROM_USERNAME_AND_CLIENT_SELECT_STATEMENT = "select token_id, auth_token from oauth_access_token_by_user_name where user_name = ? and client_id = ?";

    private static final String DEFAULT_ACCESS_TOKENS_FROM_USERNAME_SELECT_STATEMENT = "select token_id, auth_token from oauth_access_token_by_user_name where user_name = ?";

    private static final String DEFAULT_ACCESS_TOKENS_FROM_CLIENTID_SELECT_STATEMENT = "select token_id, auth_token from oauth_access_token_by_client_id where client_id = ?";

    private static final String DEFAULT_ACCESS_TOKEN_DELETE_STATEMENT = "delete from oauth_access_token where token_id = ?";

    private static final String DEFAULT_ACCESS_TOKEN_FROM_REFRESH_TOKEN_SELECT_STATEMENT = "select token_id, auth_token from oauth_access_token_by_refresh_token where refresh_token = ?";

    /** oauth_refresh_token table */
    private static final String DEFAULT_REFRESH_TOKEN_INSERT_STATEMENT = "insert into oauth_refresh_token (token_id, refresh_token, authentication) values (?, ?, ?)";

    private static final String DEFAULT_REFRESH_TOKEN_SELECT_STATEMENT = "select token_id, refresh_token from oauth_refresh_token where token_id = ?";

    private static final String DEFAULT_REFRESH_TOKEN_AUTHENTICATION_SELECT_STATEMENT = "select token_id, authentication from oauth_refresh_token where token_id = ?";

    private static final String DEFAULT_REFRESH_TOKEN_DELETE_STATEMENT = "delete from oauth_refresh_token where token_id = ?";

    private String insertAccessTokenCql = DEFAULT_ACCESS_TOKEN_INSERT_STATEMENT;

    private String selectAccessTokenCql = DEFAULT_ACCESS_TOKEN_SELECT_STATEMENT;

    private String selectAccessTokenAuthenticationCql = DEFAULT_ACCESS_TOKEN_AUTHENTICATION_SELECT_STATEMENT;

    private String selectAccessTokenFromAuthenticationCql = DEFAULT_ACCESS_TOKEN_FROM_AUTHENTICATION_SELECT_STATEMENT;

    private String selectAccessTokensFromUserNameAndClientIdCql = DEFAULT_ACCESS_TOKENS_FROM_USERNAME_AND_CLIENT_SELECT_STATEMENT;

    private String selectAccessTokensFromUserNameCql = DEFAULT_ACCESS_TOKENS_FROM_USERNAME_SELECT_STATEMENT;

    private String selectAccessTokensFromClientIdCql = DEFAULT_ACCESS_TOKENS_FROM_CLIENTID_SELECT_STATEMENT;

    private String deleteAccessTokenCql = DEFAULT_ACCESS_TOKEN_DELETE_STATEMENT;

    private String insertRefreshTokenCql = DEFAULT_REFRESH_TOKEN_INSERT_STATEMENT;

    private String selectRefreshTokenCql = DEFAULT_REFRESH_TOKEN_SELECT_STATEMENT;

    private String selectRefreshTokenAuthenticationCql = DEFAULT_REFRESH_TOKEN_AUTHENTICATION_SELECT_STATEMENT;

    private String deleteRefreshTokenCql = DEFAULT_REFRESH_TOKEN_DELETE_STATEMENT;

    private String selectAccessTokensFromRefreshTokenCql = DEFAULT_ACCESS_TOKEN_FROM_REFRESH_TOKEN_SELECT_STATEMENT;

    private AuthenticationKeyGenerator authenticationKeyGenerator = new DefaultAuthenticationKeyGenerator();

    private Session session;

    private Map<String, PreparedStatement> preparedStatementMap;

    public CassandraTokenStore(Session session){
        Assert.notNull(session, "Cassandra session should not be null value.");
        this.session = session;
        prepareStatements();
    }

    public void prepareStatements(){
        preparedStatementMap = new HashMap<>(13);
        preparedStatementMap.put("insertAccessTokenCql", session.prepare(insertAccessTokenCql));
        preparedStatementMap.put("selectAccessTokenCql", session.prepare(selectAccessTokenCql));
        preparedStatementMap.put("selectAccessTokenAuthenticationCql", session.prepare(selectAccessTokenAuthenticationCql));
        preparedStatementMap.put("selectAccessTokenFromAuthenticationCql", session.prepare(selectAccessTokenFromAuthenticationCql));
        preparedStatementMap.put("selectAccessTokensFromUserNameAndClientIdCql", session.prepare(selectAccessTokensFromUserNameAndClientIdCql));
        preparedStatementMap.put("selectAccessTokensFromUserNameCql", session.prepare(selectAccessTokensFromUserNameCql));
        preparedStatementMap.put("selectAccessTokensFromClientIdCql", session.prepare(selectAccessTokensFromClientIdCql));
        preparedStatementMap.put("deleteAccessTokenCql", session.prepare(deleteAccessTokenCql));
        preparedStatementMap.put("insertRefreshTokenCql", session.prepare(insertRefreshTokenCql));
        preparedStatementMap.put("selectRefreshTokenCql", session.prepare(selectRefreshTokenCql));
        preparedStatementMap.put("selectRefreshTokenAuthenticationCql", session.prepare(selectRefreshTokenAuthenticationCql));
        preparedStatementMap.put("deleteRefreshTokenCql", session.prepare(deleteRefreshTokenCql));
        preparedStatementMap.put("selectAccessTokensFromRefreshTokenCql", session.prepare(selectAccessTokensFromRefreshTokenCql));
    }

    public void setAuthenticationKeyGenerator(AuthenticationKeyGenerator authenticationKeyGenerator) {
        this.authenticationKeyGenerator = authenticationKeyGenerator;
    }

    @Override
    public OAuth2Authentication readAuthentication(OAuth2AccessToken token) {
        return readAuthentication(token.getValue());
    }

    @Override
    public OAuth2Authentication readAuthentication(String token) {
        OAuth2Authentication authentication = null;
        Collection<OAuth2Authentication> authentications;

        BoundStatement bs = new BoundStatement(preparedStatementMap.get("selectAccessTokenAuthenticationCql"));
        bs.bind(extractTokenKey(token));

        try {
            ResultSet rs = session.execute(bs);
            authentications = getAuthenticationsFromResultSet(rs);
            if (authentications.isEmpty()) {
                if (LOG.isInfoEnabled()) {
                    LOG.info("Failed to find access token for token " + token);
                }
            } else {
                authentication = authentications.iterator().next();
            }
        } catch (IllegalArgumentException e) {
            LOG.warn("Failed to deserialize authentication for " + token, e);
            removeAccessToken(token);
        }

        return authentication;
    }

    @Override
    public void storeAccessToken(OAuth2AccessToken token, OAuth2Authentication authentication) {
        String refreshToken = null;

        if (token.getRefreshToken() != null) {
            refreshToken = token.getRefreshToken().getValue();
        }

        if (readAccessToken(token.getValue()) != null) {
            removeAccessToken(token.getValue());
        }

        BoundStatement bs = new BoundStatement(preparedStatementMap.get("insertAccessTokenCql"));
        bs.bind(
                extractTokenKey(token.getValue()),
                serializeAccessToken(token),
                authenticationKeyGenerator.extractKey(authentication),
                authentication.isClientOnly() ? null : authentication.getName(),
                authentication.getOAuth2Request().getClientId(),
                serializeAuthentication(authentication),
                extractTokenKey(refreshToken)
        );
        session.execute(bs);
    }

    @Override
    public OAuth2AccessToken readAccessToken(String tokenValue) {
        OAuth2AccessToken accessToken = null;
        Collection<OAuth2AccessToken> accessTokens;

        BoundStatement bs = new BoundStatement(preparedStatementMap.get("selectAccessTokenCql"));
        bs.bind(extractTokenKey(tokenValue));

        ResultSet rs = session.execute(bs);
        accessTokens = getAuthTokensFromResultSet(rs);
        if (accessTokens.isEmpty()) {
            if (LOG.isInfoEnabled()) {
                LOG.info("Failed to find access token for token " + tokenValue);
            }
        } else {
            accessToken = accessTokens.iterator().next();
        }
        return accessToken;
    }

    @Override
    public void removeAccessToken(OAuth2AccessToken token) {
        removeAccessToken(token.getValue());
    }

    public void removeAccessToken(String tokenValue) {
        BoundStatement bs = new BoundStatement(preparedStatementMap.get("deleteAccessTokenCql"));
        bs.bind(extractTokenKey(tokenValue));
        session.execute(bs);
    }

    @Override
    public void storeRefreshToken(OAuth2RefreshToken refreshToken, OAuth2Authentication authentication) {
        BoundStatement bs = new BoundStatement(preparedStatementMap.get("insertRefreshTokenCql"));
        bs.bind(
                extractTokenKey(refreshToken.getValue()),
                serializeRefreshToken(refreshToken),
                serializeAuthentication(authentication)
        );
        session.execute(bs);
    }

    @Override
    public OAuth2RefreshToken readRefreshToken(String token) {
        OAuth2RefreshToken refreshToken = null;

        BoundStatement bs = new BoundStatement(preparedStatementMap.get("selectRefreshTokenCql"));
        bs.bind(extractTokenKey(token));
        ResultSet rs = session.execute(bs);

        try {
            refreshToken = getRefreshTokenFromResultSet(rs);
        } catch (IllegalArgumentException e) {
            LOG.warn("Failed to deserialize refresh token for token " + token, e);
            removeRefreshToken(token);
        }
        if (refreshToken == null) {
            if (LOG.isInfoEnabled()) {
                LOG.info("Failed to find refresh token for token " + token);
            }
        }
        return refreshToken;
    }

    @Override
    public OAuth2Authentication readAuthenticationForRefreshToken(OAuth2RefreshToken token) {
        return readAuthenticationForRefreshToken(token.getValue());
    }

    public OAuth2Authentication readAuthenticationForRefreshToken(String value) {
        OAuth2Authentication authentication = null;

        BoundStatement bs = new BoundStatement(preparedStatementMap.get("selectRefreshTokenAuthenticationCql"));
        bs.bind(extractTokenKey(value));
        ResultSet rs = session.execute(bs);

        try {
            Collection<OAuth2Authentication> authentications = getAuthenticationsFromResultSet(rs);
            if (authentications.isEmpty()) {
                if (LOG.isInfoEnabled()) {
                    LOG.info("Failed to find access token for token " + value);
                }
            } else {
                authentication = authentications.iterator().next();
            }
        } catch (IllegalArgumentException e) {
            LOG.warn("Failed to deserialize access token for " + value, e);
            removeRefreshToken(value);
        }
        return authentication;
    }

    @Override
    public void removeRefreshToken(OAuth2RefreshToken token) {
        removeRefreshToken(token.getValue());
    }

    public void removeRefreshToken(String token) {
        BoundStatement bs = new BoundStatement(preparedStatementMap.get("deleteRefreshTokenCql"));
        bs.bind(extractTokenKey(token));

        session.execute(bs);
    }

    @Override
    public void removeAccessTokenUsingRefreshToken(OAuth2RefreshToken refreshToken) {
        removeAccessTokenUsingRefreshToken(refreshToken.getValue());
    }

    public void removeAccessTokenUsingRefreshToken(String refreshToken) {
        BoundStatement bs = new BoundStatement(preparedStatementMap.get("selectAccessTokensFromRefreshTokenCql"));
        bs.bind(extractTokenKey(refreshToken));

        ResultSet rs = session.execute(bs);
        
        Collection<OAuth2AccessToken> accessTokens = getAuthTokensFromResultSet(rs);
        if (!accessTokens.isEmpty()) {
            Collection<String> tokensToDelete = accessTokens.stream()
                    .map(OAuth2AccessToken::getValue)
                    .collect(Collectors.toList());

            tokensToDelete.forEach(tokenToDeleteId -> {
                session.execute(preparedStatementMap.get("deleteAccessTokenCql").bind(tokenToDeleteId));
            });
        }
    }

    @Override
    public OAuth2AccessToken getAccessToken(OAuth2Authentication authentication) {
        OAuth2AccessToken accessToken = null;
        String key = authenticationKeyGenerator.extractKey(authentication);

        BoundStatement bs = new BoundStatement(preparedStatementMap.get("selectAccessTokenFromAuthenticationCql"));
        bs.bind(key);
        ResultSet rs = session.execute(bs);

        Collection<OAuth2AccessToken> accessTokens = getAuthTokensFromResultSet(rs);
        if (accessTokens.isEmpty()) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Failed to find access token for authentication " + authentication);
            }
        } else {
            accessToken = accessTokens.iterator().next();
        }


        if (accessToken != null
                && !key.equals(authenticationKeyGenerator.extractKey(readAuthentication(accessToken.getValue())))) {
            removeAccessToken(accessToken.getValue());
            // Keep the store consistent (maybe the same user is represented by this authentication but the details have
            // changed)
            storeAccessToken(accessToken, authentication);
        }

        return accessToken;
    }

    @Override
    public Collection<OAuth2AccessToken> findTokensByClientIdAndUserName(String clientId, String userName) {
        BoundStatement bs = new BoundStatement(preparedStatementMap.get("selectAccessTokensFromUserNameAndClientIdCql"));
        bs.bind(userName, clientId);

        ResultSet rs = session.execute(bs);
        List<OAuth2AccessToken> accessTokens = getAuthTokensFromResultSet(rs);
        if (accessTokens.isEmpty()) {
            if (LOG.isInfoEnabled()) {
                LOG.info("Failed to find access token for clientId " + clientId + " and userName " + userName);
            }
        }

        accessTokens = removeNulls(accessTokens);

        return accessTokens;
    }

    @Override
    public Collection<OAuth2AccessToken> findTokensByClientId(String clientId) {
        BoundStatement bs = new BoundStatement(preparedStatementMap.get("selectAccessTokensFromClientIdCql"));
        bs.bind(clientId);

        ResultSet rs = session.execute(bs);
        List<OAuth2AccessToken> accessTokens = getAuthTokensFromResultSet(rs);
        if (accessTokens.isEmpty()) {
            if (LOG.isInfoEnabled()) {
                LOG.info("Failed to find access token for clientId " + clientId);
            }
        }

        accessTokens = removeNulls(accessTokens);
        return accessTokens;
    }

    public Collection<OAuth2AccessToken> findTokensByUserName(String userName) {
        BoundStatement bs = new BoundStatement(preparedStatementMap.get("selectAccessTokensFromUserNameCql"));
        bs.bind(userName);

        ResultSet rs = session.execute(bs);
        List<OAuth2AccessToken> accessTokens = getAuthTokensFromResultSet(rs);
        if (accessTokens.isEmpty()) {
            if (LOG.isInfoEnabled()) {
                LOG.info("Failed to find access token for userName " + userName);
            }
        }

        accessTokens = removeNulls(accessTokens);
        return accessTokens;
    }

    public void setInsertAccessTokenSql(String insertAccessTokenCql) {
        this.insertAccessTokenCql = insertAccessTokenCql;
        preparedStatementMap.put("insertAccessTokenCql", session.prepare(insertAccessTokenCql));
    }

    public void setSelectAccessTokenSql(String selectAccessTokenCql) {
        this.selectAccessTokenCql = selectAccessTokenCql;
        preparedStatementMap.put("selectAccessTokenCql", session.prepare(selectAccessTokenCql));
    }

    public void setDeleteAccessTokenSql(String deleteAccessTokenCql) {
        this.deleteAccessTokenCql = deleteAccessTokenCql;
        preparedStatementMap.put("deleteAccessTokenCql", session.prepare(deleteAccessTokenCql));
    }

    public void setInsertRefreshTokenSql(String insertRefreshTokenCql) {
        this.insertRefreshTokenCql = insertRefreshTokenCql;
        preparedStatementMap.put("insertRefreshTokenCql", session.prepare(insertRefreshTokenCql));
    }

    public void setSelectRefreshTokenSql(String selectRefreshTokenCql) {
        this.selectRefreshTokenCql = selectRefreshTokenCql;
        preparedStatementMap.put("selectRefreshTokenCql", session.prepare(selectRefreshTokenCql));
    }

    public void setDeleteRefreshTokenSql(String deleteRefreshTokenCql) {
        this.deleteRefreshTokenCql = deleteRefreshTokenCql;
        preparedStatementMap.put("deleteRefreshTokenCql", session.prepare(deleteRefreshTokenCql));
    }

    public void setSelectAccessTokenAuthenticationSql(String selectAccessTokenAuthenticationCql) {
        this.selectAccessTokenAuthenticationCql = selectAccessTokenAuthenticationCql;
        preparedStatementMap.put("selectAccessTokenAuthenticationCql", session.prepare(selectAccessTokenAuthenticationCql));
    }

    public void setSelectRefreshTokenAuthenticationSql(String selectRefreshTokenAuthenticationCql) {
        this.selectRefreshTokenAuthenticationCql = selectRefreshTokenAuthenticationCql;
        preparedStatementMap.put("selectRefreshTokenAuthenticationCql", session.prepare(selectRefreshTokenAuthenticationCql));
    }

    public void setSelectAccessTokenFromAuthenticationSql(String selectAccessTokenFromAuthenticationCql) {
        this.selectAccessTokenFromAuthenticationCql = selectAccessTokenFromAuthenticationCql;
        preparedStatementMap.put("selectAccessTokenFromAuthenticationCql", session.prepare(selectAccessTokenFromAuthenticationCql));
    }

    public void setDeleteAccessTokenFromRefreshTokenSql(String selectAccessTokensFromRefreshTokenCql) {
        this.selectAccessTokensFromRefreshTokenCql = selectAccessTokensFromRefreshTokenCql;
        preparedStatementMap.put("selectAccessTokensFromRefreshTokenCql", session.prepare(selectAccessTokensFromRefreshTokenCql));
    }

    public void setSelectAccessTokensFromUserNameSql(String selectAccessTokensFromUserNameCql) {
        this.selectAccessTokensFromUserNameCql = selectAccessTokensFromUserNameCql;
        preparedStatementMap.put("selectAccessTokensFromUserNameCql", session.prepare(selectAccessTokensFromUserNameCql));
    }

    public void setSelectAccessTokensFromUserNameAndClientIdSql(String selectAccessTokensFromUserNameAndClientIdCql) {
        this.selectAccessTokensFromUserNameAndClientIdCql = selectAccessTokensFromUserNameAndClientIdCql;
        preparedStatementMap.put("selectAccessTokensFromUserNameAndClientIdCql", session.prepare(selectAccessTokensFromUserNameAndClientIdCql));
    }

    public void setSelectAccessTokensFromClientIdSql(String selectAccessTokensFromClientIdCql) {
        this.selectAccessTokensFromClientIdCql = selectAccessTokensFromClientIdCql;
        preparedStatementMap.put("selectAccessTokensFromClientIdCql", session.prepare(selectAccessTokensFromClientIdCql));

    }

    protected String extractTokenKey(String value) {
        if (value == null) {
            return null;
        }
        MessageDigest digest;
        try {
            digest = MessageDigest.getInstance("MD5");
        }
        catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("MD5 algorithm not available.  Fatal (should be in the JDK).");
        }

        try {
            byte[] bytes = digest.digest(value.getBytes("UTF-8"));
            return String.format("%032x", new BigInteger(1, bytes));
        }
        catch (UnsupportedEncodingException e) {
            throw new IllegalStateException("UTF-8 encoding not available.  Fatal (should be in the JDK).");
        }
    }

    protected ByteBuffer serializeAccessToken(OAuth2AccessToken token) {
        return ByteBuffer.wrap(SerializationUtils.serialize(token));
    }

    protected ByteBuffer serializeRefreshToken(OAuth2RefreshToken token) {
        return ByteBuffer.wrap(SerializationUtils.serialize(token));
    }

    protected ByteBuffer serializeAuthentication(OAuth2Authentication authentication) {
        return ByteBuffer.wrap(SerializationUtils.serialize(authentication));
    }

    protected OAuth2AccessToken deserializeAccessToken(ByteBuffer token) {
        return SerializationUtils.deserialize(getBytesFromByteBuffer(token));
    }

    protected OAuth2RefreshToken deserializeRefreshToken(ByteBuffer token) {
        return SerializationUtils.deserialize(getBytesFromByteBuffer(token));
    }

    protected OAuth2Authentication deserializeAuthentication(ByteBuffer authentication) {
        return SerializationUtils.deserialize(getBytesFromByteBuffer(authentication));
    }

    private List<OAuth2AccessToken> removeNulls(List<OAuth2AccessToken> accessTokens) {
        List<OAuth2AccessToken> tokens = new ArrayList<OAuth2AccessToken>();
        for (OAuth2AccessToken token : accessTokens) {
            if (token != null) {
                tokens.add(token);
            }
        }
        return tokens;
    }

    private List<OAuth2Authentication> getAuthenticationsFromResultSet(ResultSet rs) {
        List<OAuth2Authentication> result = new ArrayList<>();
        for (Row row: rs) {
            ByteBuffer bb = row.getBytes("authentication");
            result.add(deserializeAuthentication(bb));
        };
        return result;
    }

    private List<OAuth2AccessToken> getAuthTokensFromResultSet(ResultSet rs) {
        List<OAuth2AccessToken> result = new ArrayList<>();
        for (Row row: rs) {
            ByteBuffer bb = row.getBytes("auth_token");
            try {
                result.add(deserializeAccessToken(bb));
            } catch (IllegalArgumentException e) {
                String token_id = row.getString("token_id");
                session.execute(preparedStatementMap.get("deleteAccessTokenCql").bind(token_id));
            }
        };

        return result;
    }

    private OAuth2RefreshToken getRefreshTokenFromResultSet(ResultSet rs) {
        Row row = rs.one();
        if (row == null) {
            return null;
        }
        ByteBuffer bb = row.getBytes("refresh_token");
        return deserializeRefreshToken(bb);
    }

    private byte[] getBytesFromByteBuffer(ByteBuffer bb) {
        byte[] bytes = new byte[bb.remaining()];
        bb.get(bytes);
        return bytes;
    }

}
