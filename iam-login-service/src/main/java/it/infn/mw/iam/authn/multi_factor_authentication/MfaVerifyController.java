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
package it.infn.mw.iam.authn.multi_factor_authentication;

import static it.infn.mw.iam.authn.multi_factor_authentication.MfaVerifyController.MFA_VERIFY_URL;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

//TODO when unauthenticated and navigating to other pages like /dashboard, we redirect to /login. But here we show up as unauthorized. Can we replicate the behaviour of /dashboard?

@Controller
@RequestMapping(MFA_VERIFY_URL)
public class MfaVerifyController {

  // TODO - step up authentication page can't read SPRING_SECURITY_LAST_EXCEPTION.message to display
  // "Bad code" error. Fix this and use
  // ExternalAuthenticationHandlerSupport.saveAuthenticationErrorInSession() as a reference

  public static final String MFA_VERIFY_URL = "/iam/verify";

  @Autowired
  public MfaVerifyController() {}

  @PreAuthorize("hasRole('PRE_AUTHENTICATED')")
  @RequestMapping(method = RequestMethod.GET, path = "")
  public String getVerifyMfaView() {
    return "iam/verify-mfa";
  }
}
