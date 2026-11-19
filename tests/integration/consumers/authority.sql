-- Read-only integration fixture, never a migration. Own disposable database only.
CREATE SCHEMA fixture;
CREATE SCHEMA diretorio;
CREATE SCHEMA diretoriov2;
CREATE TABLE fixture.profiles(email text PRIMARY KEY, profile jsonb NOT NULL);
CREATE TABLE fixture.violations(id bigserial PRIMARY KEY);
CREATE TABLE diretorio.contas(id bigint PRIMARY KEY, email text, nome text, ativo int, tipo text);
CREATE TABLE diretoriov2.service_accounts(conta_id bigint PRIMARY KEY, tenant int, version int DEFAULT 1,
    require_signature boolean DEFAULT false, allowed_cidrs cidr[] DEFAULT '{}', revoked_at timestamptz);
CREATE TABLE diretoriov2.service_account_keys(prefix text PRIMARY KEY, conta_id bigint, secret_hmac text,
    expires_at timestamptz, revoked_at timestamptz);
CREATE TABLE diretoriov2.service_account_tenant_policy(tenant int PRIMARY KEY, require_signature boolean);
CREATE TABLE diretoriov2.service_account_blocked_cidrs(cidr cidr, removed_at timestamptz);
CREATE TABLE diretoriov2.service_account_public_keys(conta_id bigint, key_id text, algorithm text,
    public_key_pem text, revoked_at timestamptz);
CREATE TABLE diretoriov2.seats(id bigint PRIMARY KEY, tenant int, enabled boolean, retired_at timestamptz);
CREATE TABLE diretoriov2.service_account_global_seats(conta_id bigint, seat_id bigint);
CREATE TABLE diretoriov2.tenant_available_seats(tenant int, seat_id bigint);
INSERT INTO diretoriov2.service_account_blocked_cidrs(cidr) VALUES ('10.0.0.0/8'), ('127.0.0.0/8'), ('172.16.0.0/12'), ('192.168.0.0/16');
