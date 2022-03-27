create table Users (
    id serial primary key,
    username varchar unique,
    password_hash varchar
);

create table Projects(
    id serial primary key,
    owner integer,
    name varchar unique,
    description varchar,
    public BOOLEAN
);

create table Issues (
    id serial primary key,
    project_id integer,
    title varchar[31],
    description varchar
);