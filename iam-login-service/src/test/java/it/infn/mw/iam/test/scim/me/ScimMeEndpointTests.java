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
package it.infn.mw.iam.test.scim.me;

import static it.infn.mw.iam.api.scim.model.ScimConstants.SCIM_CONTENT_TYPE;
import static it.infn.mw.iam.api.scim.model.ScimIndigoUser.INDIGO_USER_SCHEMA.ATTRIBUTES;
import static it.infn.mw.iam.api.scim.model.ScimIndigoUser.INDIGO_USER_SCHEMA.AUP_SIGNATURE_TIME;
import static it.infn.mw.iam.api.scim.model.ScimIndigoUser.INDIGO_USER_SCHEMA.LABELS;
import static it.infn.mw.iam.api.scim.model.ScimIndigoUser.INDIGO_USER_SCHEMA.MANAGED_GROUPS;
import static java.lang.String.valueOf;
import static org.hamcrest.Matchers.equalTo;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.web.servlet.MockMvc;

import it.infn.mw.iam.test.util.WithMockOAuthUser;
import it.infn.mw.iam.test.util.annotation.IamMockMvcIntegrationTest;
import it.infn.mw.iam.test.util.oauth.MockOAuth2Filter;


@RunWith(SpringJUnit4ClassRunner.class)
@IamMockMvcIntegrationTest
public class ScimMeEndpointTests {

  private final static String ME_ENDPOINT = "/scim/Me";

  @Autowired
  private MockOAuth2Filter mockOAuth2Filter;

  @Autowired
  private MockMvc mvc;

  @Before
  public void setup() throws Exception {
    mockOAuth2Filter.cleanupSecurityContext();
  }

  @After
  public void teardown() {
    mockOAuth2Filter.cleanupSecurityContext();
  }

  private void getScimMeAsUserIsOk() throws Exception {
    //@formatter:off
    mvc.perform(get(ME_ENDPOINT)
        .contentType(SCIM_CONTENT_TYPE))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$." + AUP_SIGNATURE_TIME).doesNotExist())
      .andExpect(jsonPath("$." + ATTRIBUTES).doesNotExist())
      .andExpect(jsonPath("$." + LABELS).doesNotExist())
      .andExpect(jsonPath("$." + MANAGED_GROUPS).doesNotExist());
    //@formatter:on
  }

  private void getScimMeAsUserIsError(int statusCode, String message) throws Exception {

    mvc.perform(get(ME_ENDPOINT).contentType(SCIM_CONTENT_TYPE))
      .andExpect(status().isBadRequest())
      .andExpect(jsonPath("$.status", equalTo(valueOf(statusCode))))
      .andExpect(jsonPath("$.detail", equalTo(message)));
  }

  @Test
  @WithMockOAuthUser(clientId = "password-grant", user = "test", scopes = {"scim:read"},
      authorities = {"ROLE_USER"})
  public void meEndpointUserInfoWithTokenAndScimReadScope() throws Exception {

    getScimMeAsUserIsOk();
  }

  @Test
  @WithMockUser(username = "test", roles = {"USER"})
  public void meEndpointUserInfoNoToken() throws Exception {

    getScimMeAsUserIsOk();
  }

  @Test
  @WithMockOAuthUser(clientId = "registration-client", scopes = {"scim:read"})
  public void meEndpointFailsWithClientCredentials() throws Exception {

    getScimMeAsUserIsError(400, "No user linked to the current OAuth token");
  }

  @Test
  @WithMockOAuthUser(clientId = "password-grant", user = "test", scopes = {"opeind", "profile"},
      authorities = {"ROLE_USER"})
  public void meEndpointSuccessWithTokenButNoScimScopes() throws Exception {

    getScimMeAsUserIsOk();
  }
}
