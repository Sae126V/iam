CREATE TABLE iam_cert_link_request (
    ID BIGINT IDENTITY NOT NULL,
    UUID VARCHAR(36) NOT NULL UNIQUE,
    ACCOUNT_ID BIGINT,
    IAM_X509_CERT_ID BIGINT,
    STATUS VARCHAR(50),
    NOTES CLOB,
    MOTIVATION CLOB,
    CREATIONTIME TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    LASTUPDATETIME TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (ID));

ALTER TABLE iam_cert_link_request ADD CONSTRAINT FK_iam_cert_link_request_account_id FOREIGN KEY (ACCOUNT_ID) REFERENCES iam_account (ID);
ALTER TABLE iam_cert_link_request ADD CONSTRAINT FK_iam_cert_link_request_x509_cert_id FOREIGN KEY (IAM_X509_CERT_ID) REFERENCES IAM_X509_CERT (ID);
