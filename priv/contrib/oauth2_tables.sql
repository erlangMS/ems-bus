Scripts SQL para habilitar a persistência de tokens OAuth2 no SGBD e habilitar a funcionalidade de passport
=======================================================================================================================

create table dbsm.erlangms_oauth2_access_code(
    id varchar(60) not null primary key, 
    dt_registro date not null, 
    context varchar(4000) not null
)
GO

create table dbsm.erlangms_oauth2_refresh_token(
    id varchar(60) not null primary key, 
    dt_registro date not null, 
    context varchar(4000) not null
)
GO

create table dbsm.erlangms_oauth2_access_token(
    id varchar(60) not null primary key, 
    dt_registro date not null, 
    context varchar(4000) not null
)
GO

create table dbsm.erlangms_passport(id integer not null primary key, 
                                      clientid integer not null, 
                                      userid integer not null, 
                                      dt_created date not null, 
                                      dt_disabled date,
                                      scope varchar(120),
                                      active  integer not null default 1)
GO

