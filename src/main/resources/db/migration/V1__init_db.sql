create sequence if not exists seq_user_id start 1 increment 1;

create table if not exists usuarios
(
	id int not null,
	nome varchar(255),
	login varchar(255),
	senha varchar(255),
	role varchar(255),

	primary key(id)
);