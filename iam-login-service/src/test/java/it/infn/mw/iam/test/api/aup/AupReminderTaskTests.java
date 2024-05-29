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
package it.infn.mw.iam.test.api.aup;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.Date;

import org.junit.After;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.api.aup.model.AupConverter;
import it.infn.mw.iam.api.aup.model.AupDTO;
import it.infn.mw.iam.core.web.aup.AupReminderTask;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.persistence.repository.IamAupSignatureRepository;
import it.infn.mw.iam.persistence.repository.IamEmailNotificationRepository;
import it.infn.mw.iam.service.aup.DefaultAupSignatureCheckService;
import it.infn.mw.iam.test.core.CoreControllerTestSupport;
import it.infn.mw.iam.test.notification.NotificationTestConfig;
import it.infn.mw.iam.test.util.WithAnonymousUser;
import it.infn.mw.iam.test.util.annotation.IamMockMvcIntegrationTest;
import it.infn.mw.iam.test.util.notification.MockNotificationDelivery;

@RunWith(SpringRunner.class)
@IamMockMvcIntegrationTest
@SpringBootTest(classes = {IamLoginService.class, CoreControllerTestSupport.class,
    NotificationTestConfig.class}, webEnvironment = WebEnvironment.MOCK)
@WithAnonymousUser
@TestPropertySource(properties = {"notification.disable=false"})
public class AupReminderTaskTests extends AupTestSupport {

  @Autowired
  private AupConverter converter;

  @Autowired
  private ObjectMapper mapper;

  @Autowired
  private DefaultAupSignatureCheckService service;

  @Autowired
  private IamAccountRepository accountRepo;

  @Autowired
  private IamAupSignatureRepository signatureRepo;

  @Autowired
  private MockMvc mvc;

  @Autowired
  private IamEmailNotificationRepository notificationRepo;

  @Autowired
  private AupReminderTask aupTask;

  @Autowired
  private MockNotificationDelivery notificationDelivery;

  @After
  public void tearDown() throws InterruptedException {
    notificationDelivery.clearDeliveredNotifications();
  }

  @Test
  @WithMockUser(username = "admin", roles = {"ADMIN", "USER"})
  public void aupReminderEmailWorks() throws JsonProcessingException, Exception {
    AupDTO aup = converter.dtoFromEntity(buildDefaultAup());
    aup.setSignatureValidityInDays(30L);

    Date now = new Date();

    mvc
      .perform(
          post("/iam/aup").contentType(APPLICATION_JSON).content(mapper.writeValueAsString(aup)))
      .andExpect(status().isCreated());


    IamAccount testAccount = accountRepo.findByUsername("test")
      .orElseThrow(() -> new AssertionError("Expected test account not found"));

    assertThat(service.needsAupSignature(testAccount), is(true));

    signatureRepo.createSignatureForAccount(testAccount, now);

    assertThat(service.needsAupSignature(testAccount), is(false));

    assertThat(notificationRepo.countAupRemindersPerAccount(testAccount.getUserInfo().getEmail()),
        equalTo(0));

    aupTask.sendAupReminders();
    notificationDelivery.sendPendingNotifications();
    assertThat(notificationRepo.countAupRemindersPerAccount(testAccount.getUserInfo().getEmail()),
        equalTo(1));

  }
}
