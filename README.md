# authUtils
Custom authentication and authorization utils for Spring Security.

Classes:

-- CassandraTokenStore - implementation of TokenStore with Cassandra.

-- CassandraClientDetailsService - implementation of ClientDetailsService with Cassandra.

-- CassandraClientDetailsServiceBuilder - extends ClientDetailsServiceBuilder, allows to build CassandraClientDetailsService.

-- ServiceTokenGranter - implementation of token granter for trusted services.

Sample configuration files for OAuath authorization are in config directory.


Test CQL schema can be found in /test/resources in file "oauth_test.cql"
