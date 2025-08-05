CREATE TABLE iam_totp_admin_key (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    admin_mfa_key VARCHAR(255) NOT NULL,
    last_update_time TIMESTAMP NOT NULL
);
