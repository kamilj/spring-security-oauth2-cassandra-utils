CREATE KEYSPACE IF NOT EXISTS token_store_test
WITH replication = {
	'class' : 'SimpleStrategy',
	'replication_factor' : 1
};

// Create tables
// oauth_access_token
CREATE TABLE IF NOT EXISTS token_store_test.oauth_access_token (
  token_id varchar,
  auth_token blob,
  authentication_id varchar,
  user_name varchar,
  client_id varchar,
  authentication blob,
  refresh_token varchar,
  PRIMARY KEY((token_id), client_id)
);

CREATE MATERIALIZED VIEW IF NOT EXISTS token_store_test.oauth_access_token_by_authentication_id AS
  SELECT *
  FROM oauth_access_token
  WHERE token_id IS NOT NULL
  AND authentication_id IS NOT NULL
  AND client_id IS NOT NULL
  PRIMARY KEY (authentication_id, token_id, client_id);

CREATE MATERIALIZED VIEW IF NOT EXISTS token_store_test.oauth_access_token_by_user_name AS
  SELECT *
  FROM oauth_access_token
  WHERE token_id IS NOT NULL
  AND user_name IS NOT NULL
  AND client_id IS NOT NULL
  PRIMARY KEY (user_name, client_id, token_id);

CREATE MATERIALIZED VIEW IF NOT EXISTS token_store_test.oauth_access_token_by_client_id AS
  SELECT *
  FROM oauth_access_token
  WHERE token_id IS NOT NULL
  AND client_id IS NOT NULL
  PRIMARY KEY (client_id, token_id);

CREATE MATERIALIZED VIEW IF NOT EXISTS token_store_test.oauth_access_token_by_refresh_token AS
  SELECT *
  FROM oauth_access_token
  WHERE token_id IS NOT NULL
  AND refresh_token IS NOT NULL
  AND client_id IS NOT NULL
  PRIMARY KEY (refresh_token, token_id, client_id);

// oauth_refresh_token
CREATE TABLE IF NOT EXISTS token_store_test.oauth_refresh_token (
  token_id varchar,
  refresh_token blob,
  authentication blob,
  PRIMARY KEY(token_id)
);