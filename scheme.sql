CREATE TABLE stat (
  time              timestamp WITHOUT TIME ZONE NOT NULL,
  vlan_id           smallint NOT NULL,
  filter	    varchar(40) NOT NULL DEFAULT '',
  proto             smallint NOT NULL,
  saddr             inet NOT NULL,
  sport             integer NOT NULL,
  daddr             inet NOT NULL,
  dport             integer NOT NULL,
  dsubnet           cidr NOT NULL,
  bytes             bigint NOT NULL,
  packets           bigint NOT NULL
);
