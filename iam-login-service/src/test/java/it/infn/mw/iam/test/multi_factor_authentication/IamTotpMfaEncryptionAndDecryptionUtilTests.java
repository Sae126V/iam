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
package it.infn.mw.iam.test.multi_factor_authentication;

import static org.junit.Assert.assertTrue;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.junit.MockitoJUnitRunner;

import it.infn.mw.iam.util.mfa.IamTotpMfaEncryptionAndDecryptionHelper;
import it.infn.mw.iam.util.mfa.IamTotpMfaEncryptionAndDecryptionUtil;
import it.infn.mw.iam.util.mfa.IamTotpMfaInvalidArgumentError;

@RunWith(MockitoJUnitRunner.class)
public class IamTotpMfaEncryptionAndDecryptionUtilTests extends IamTotpMfaCommons {

  private static final IamTotpMfaEncryptionAndDecryptionHelper defaultModel = IamTotpMfaEncryptionAndDecryptionHelper
      .getInstance();

  @Before
  public void setUp() {
    defaultModel.setIterations(ANOTHER_ITERATIONS);
    defaultModel.setKeySize(ANOTHER_KEY_SIZE);
    defaultModel.setSaltSize(ANOTHER_SALT_SIZE);
  }

  @After
  public void tearDown() {
    defaultModel.setIterations(DEFAULT_ITERATIONS);
    defaultModel.setKeySize(DEFAULT_KEY_SIZE);
    defaultModel.setSaltSize(DEFAULT_SALT_SIZE);
  }

  @Test
  public void testEncryptionAndDecryption_SecretOrRecoveryCodeMethods() throws IamTotpMfaInvalidArgumentError {
    // Encrypt the plainText
    String cipherText = IamTotpMfaEncryptionAndDecryptionUtil.encryptSecretOrRecoveryCode(TOTP_MFA_SECRET, KEY_TO_ENCRYPT_DECRYPT);

    // Decrypt the cipherText
    String plainText = IamTotpMfaEncryptionAndDecryptionUtil.decryptSecretOrRecoveryCode(cipherText, KEY_TO_ENCRYPT_DECRYPT);

    assertEquals(TOTP_MFA_SECRET, plainText);
  }

  @Test
  public void testDecryptSecretOrRecoveryCode_WithDifferentKey() throws IamTotpMfaInvalidArgumentError {
    // Encrypt the plainText
    String cipherText = IamTotpMfaEncryptionAndDecryptionUtil.encryptSecretOrRecoveryCode(TOTP_MFA_SECRET, KEY_TO_ENCRYPT_DECRYPT);

    IamTotpMfaInvalidArgumentError thrownException = assertThrows(IamTotpMfaInvalidArgumentError.class, () -> {
      // Decrypt the cipherText with a different key
      IamTotpMfaEncryptionAndDecryptionUtil.decryptSecretOrRecoveryCode(cipherText, "NOT_THE_SAME_KEY");
    });

    assertTrue(thrownException.getMessage().startsWith("Please use the same password"));

    // Decrypt the cipherText with a the same key used for encryption.
    String plainText = IamTotpMfaEncryptionAndDecryptionUtil.decryptSecretOrRecoveryCode(cipherText, KEY_TO_ENCRYPT_DECRYPT);

    assertEquals(TOTP_MFA_SECRET, plainText);
  }

  @Test
  public void testEncryptSecretOrRecoveryCode_WithTamperedCipher() throws IamTotpMfaInvalidArgumentError {
    // Encrypt the plainText
    String cipherText = IamTotpMfaEncryptionAndDecryptionUtil.encryptSecretOrRecoveryCode(TOTP_MFA_SECRET, KEY_TO_ENCRYPT_DECRYPT);

    String modifyCipher = cipherText.substring(3);
    String tamperedCipher = "iam" + modifyCipher;

    if (!tamperedCipher.substring(0, 3).equals(cipherText.substring(0, 3))) {

      IamTotpMfaInvalidArgumentError thrownException = assertThrows(IamTotpMfaInvalidArgumentError.class, () -> {
        // Decrypt the tampered cipherText
        IamTotpMfaEncryptionAndDecryptionUtil.decryptSecretOrRecoveryCode(tamperedCipher, KEY_TO_ENCRYPT_DECRYPT);
      });

      // Always throws an error because user have tampered the cipherText.
      assertTrue(thrownException.getMessage().startsWith("Please use the same password"));
    } else {

      // Decrypt the right cipherText with a the same key used for encryption.
      String plainText = IamTotpMfaEncryptionAndDecryptionUtil.decryptSecretOrRecoveryCode(cipherText, KEY_TO_ENCRYPT_DECRYPT);

      assertEquals(TOTP_MFA_SECRET, plainText);
    }
  }

  @Test
  public void testEncryptSecretOrRecoveryCode_WithEmptyPlainText() throws IamTotpMfaInvalidArgumentError {

    IamTotpMfaInvalidArgumentError thrownException = assertThrows(IamTotpMfaInvalidArgumentError.class, () -> {
      // Try to encrypt the empty plainText
      IamTotpMfaEncryptionAndDecryptionUtil.encryptSecretOrRecoveryCode(null, KEY_TO_ENCRYPT_DECRYPT);
    });

    // Always throws an error because we have passed empty plaintext.
    assertTrue(thrownException.getMessage().startsWith("Please ensure that you provide"));
  }

  @Test
  public void testDecryptSecretOrRecoveryCode_WithEmptyPlainText() throws IamTotpMfaInvalidArgumentError {

    IamTotpMfaInvalidArgumentError thrownException = assertThrows(IamTotpMfaInvalidArgumentError.class, () -> {
      IamTotpMfaEncryptionAndDecryptionUtil.decryptSecretOrRecoveryCode(null, KEY_TO_ENCRYPT_DECRYPT);
    });

    // Always throws an error because we have passed empty ciphertext.
    assertTrue(thrownException.getMessage().startsWith("Please ensure that you provide"));
  }
}
