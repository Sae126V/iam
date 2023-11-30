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
package it.infn.mw.iam.audit.events.account.multi_factor_authentication;

import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamTotpMfa;

public class RecoveryCodeVerifiedEvent extends MultiFactorEvent {

  public static final String TEMPLATE = "MFA recovery code verified for account '%s'";

  private static final long serialVersionUID = 1L;

  public RecoveryCodeVerifiedEvent(Object source, IamAccount account, IamTotpMfa totpMfa) {
    super(source, account, totpMfa, String.format(TEMPLATE, account.getUsername()));
  }
}