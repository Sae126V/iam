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

package it.infn.mw.iam.test.login;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;

import it.infn.mw.iam.test.util.annotation.IamMockMvcIntegrationTest;

@RunWith(SpringRunner.class)
@IamMockMvcIntegrationTest
@ActiveProfiles({"h2-test", "flyway-repair", "jdbc-session"})
public class JDBCSessionLoginTests implements LoginTestSupport {

  @Autowired
  private MockMvc mvc;

  @Test
  public void testAdminSessionExists() throws Exception {
    //@formatter:off
    MockHttpSession session = (MockHttpSession) mvc
      .perform(
          post(LOGIN_URL)
            .param("username", ADMIN_USERNAME)
            .param("password", ADMIN_PASSWORD)
            .param("submit", "Login"))
      .andExpect(status().isFound())
      .andExpect(redirectedUrl("/dashboard"))
      .andReturn()
      .getRequest()
      .getSession();
    //@formatter:on
  }
}
