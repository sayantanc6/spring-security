insert into mysecuredapp.ROLE (ID, NAME) values (1,'ROLE_ADMIN');
insert into mysecuredapp.ROLE (ID, NAME) values (2,'ROLE_USER');
insert into mysecuredapp.ROLE (ID, NAME) values (3,'ROLE_guest');

-- sayantan password sayantan@123
-- sayan password sayan@123
insert into mysecuredapp.USER (ID,FIRSTNAME,LASTNAME,EMAIL,PASSWORD,ENABLED,TOKENEXPIRED,ROLES) values (11,'Sayantan','chatterjee','sayantanc6@gmail.com','af6fc640b40cde4af04e8fabdfbe34e2a4b4311f6f318dfb46369af001932b2d',true,false,'ROLE_ADMIN;ROLE_USER');
--insert into mysecuredapp.USER (ID,FIRSTNAME,LASTNAME,EMAIL,PASSWORD,ENABLED,TOKENEXPIRED,ROLES) values (12,'sayan','choudhury','sayanc6@gmail.com','052ab7438f10d82b75b448f2d1066ae097f9b82dd842074349cb13b19e188adb',true,false);

insert into mysecuredapp.users_roles (user_id, role_id) values (11,1);
--insert into mysecuredapp.users_roles (user_id, role_id) values (12,2);

insert into mysecuredapp.PRIVILEGE (ID, NAME) values (14,'read_access');
insert into mysecuredapp.PRIVILEGE (ID, NAME) values (15,'write_access');

insert into mysecuredapp.roles_privileges (role_id, privilege_id) values (1,14);
insert into mysecuredapp.roles_privileges (role_id, privilege_id) values (1,15);
insert into mysecuredapp.roles_privileges (role_id, privilege_id) values (2,14);
insert into mysecuredapp.roles_privileges (role_id, privilege_id) values (2,15);
insert into mysecuredapp.roles_privileges (role_id, privilege_id) values (3,14);