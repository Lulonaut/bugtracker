create table Users (
    id serial primary key,
    username varchar unique,
    password_hash varchar
);

create table Projects(
    id serial primary key,
    name varchar[31],
    description varchar
);

create table Issues (
    id serial primary key,
    project_id integer,
    title varchar[31],
    description varchar
);