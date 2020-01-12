create table permission
(
    id   int auto_increment
        primary key,
    name varchar(30) null,
    uri  varchar(50) null
);

create table role
(
    id        int auto_increment
        primary key,
    role_name varchar(40) null
);

create table role_permission
(
    id            int auto_increment
        primary key,
    role_id       int null,
    permission_id int null
);

create table user
(
    id       int auto_increment
        primary key,
    username varchar(40)   null,
    role_id  int           null,
    ban      int default 0 null comment '0表示禁用状态
1表示开启',
    password varchar(90)   null
);

