-- Keep product FK ids and the sole stable UOA subject reference. Profile
-- claims come from UOA on login, never from a second durable profile store.
ALTER TABLE users DROP COLUMN email;
ALTER TABLE users DROP COLUMN display_name;
