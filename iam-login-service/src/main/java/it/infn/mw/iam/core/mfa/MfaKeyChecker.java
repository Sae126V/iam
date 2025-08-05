/**
 * Copyright (c) Istituto Nazionale di Fisica Nucleare (INFN). 2016-2021
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package it.infn.mw.iam.core.mfa;

import org.flywaydb.core.internal.util.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Profile;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import it.infn.mw.iam.persistence.model.IamTotpAdminKey;
import it.infn.mw.iam.persistence.repository.IamTotpAdminKeyRepository;
import it.infn.mw.iam.util.mfa.IamTotpMfaEncryptionAndDecryptionUtil;
import it.infn.mw.iam.util.mfa.IamTotpMfaInvalidArgumentError;

import java.security.NoSuchAlgorithmException;
import javax.annotation.PostConstruct;

@Component
@Profile("mfa")
public class MfaKeyChecker {

    public static final Logger LOG = LoggerFactory.getLogger(MfaKeyChecker.class);

    private final PasswordEncoder passwordEncoder;

    @Value("${mfa.password-to-encrypt-and-decrypt}")
    private String mfaKey;

    @Value("${mfa.old-password-to-decrypt}")
    private String oldMfaKey;

    private final IamTotpAdminKeyRepository repository;
    private final JdbcTemplate jdbcTemplate;

    public MfaKeyChecker(
            IamTotpAdminKeyRepository repository,
            PasswordEncoder passwordEncoder,
            JdbcTemplate jdbcTemplate) {
        this.repository = repository;
        this.passwordEncoder = passwordEncoder;
        this.jdbcTemplate = jdbcTemplate;
    }

    @PostConstruct
    public void checkMfaKey() throws NoSuchAlgorithmException {
        String currentHash = passwordEncoder.encode(mfaKey);
        String storedHash = repository.findLatestHash();

        if (storedHash == null) {
            if (!StringUtils.hasText(mfaKey)) {
                throw new IamTotpMfaInvalidArgumentError("A key MUST be provided to use 2FA");
            }

            repository.save(new IamTotpAdminKey(currentHash));
            LOG.info("Successfully stored MFA key hash into the DB.");
        } else if (passwordEncoder.matches(mfaKey, storedHash)) {
            // Do nothing!
            LOG.info("MFA key unchanged! No action required.");
        } else {
            if ((!StringUtils.hasText(oldMfaKey))) {
                throw new IamTotpMfaInvalidArgumentError(
                        "Please provide the old key used for encrypting and decrypting secrets");
            }

            LOG.info("MFA key changed! Re-encrypting secrets with the new key.");

            // Run re-encryption
            reEncryptSecrets(oldMfaKey, mfaKey);

            // Update stored - admin key
            repository.save(new IamTotpAdminKey(currentHash));
            LOG.info("MFA key changed! Successfully completed performing encryption with the new key.");
        }
    }

    private void reEncryptSecrets(String oldKey, String newKey) {
        jdbcTemplate.query("SELECT id, secret FROM iam_totp_mfa", entry -> {
            Long id = (Long) entry.getLong("id");
            String encryptedSecret = (String) entry.getString("secret");

            try {
                String decryptedSecret = IamTotpMfaEncryptionAndDecryptionUtil.decryptSecret(encryptedSecret,
                        oldKey);
                String reEncryptedSecret = IamTotpMfaEncryptionAndDecryptionUtil.encryptSecret(decryptedSecret,
                        newKey);

                jdbcTemplate.update("UPDATE iam_totp_mfa SET secret = ? WHERE id = ?", reEncryptedSecret, id);

                LOG.info("Successfully updated secret for id {}", id);
            } catch (Exception e) {
                throw new IamTotpMfaInvalidArgumentError("Failed to re-encrypt secret for id " + id);
            }
        });
    }
}
