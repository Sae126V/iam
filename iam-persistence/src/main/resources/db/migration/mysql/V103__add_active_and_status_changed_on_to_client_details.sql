ALTER TABLE client_details ADD COLUMN (active BOOLEAN, 
                                        status_changed_on TIMESTAMP DEFAULT '1970-01-01 00:00:01',
                                        status_changed_by VARCHAR(36));