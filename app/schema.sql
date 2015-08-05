drop table if exists users;
create table users(
	id integer primary key autoincrement, 
	username text not null,
	password text not null,
	db_access_token text,
	gd_access_token text
);

drop table if exists file;
create table file(
	id integer primary key autoincrement, 
	owner integer not null,
	name text not null,
	parent text not null,
	content_path text not null,
	dropbox boolean not null,
	folder boolean not null,
	last_updated text 
);