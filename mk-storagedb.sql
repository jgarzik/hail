
create table objects (
	volume		text not null,
	hash		text not null,
	name		text not null,
	owner		text not null
);

create unique index obj_idx on objects (volume, name);

