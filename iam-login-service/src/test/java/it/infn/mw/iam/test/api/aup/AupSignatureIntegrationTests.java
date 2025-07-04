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

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.time.Instant;
import java.util.Calendar;
import java.util.Date;
import java.util.NoSuchElementException;
import java.util.Optional;

import org.apache.commons.lang.time.DateUtils;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;

import com.fasterxml.jackson.databind.ObjectMapper;

import it.infn.mw.iam.api.aup.model.AupSignatureDTO;
import it.infn.mw.iam.api.aup.model.AupSignaturePatchRequestDTO;
import it.infn.mw.iam.core.user.IamAccountService;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamAup;
import it.infn.mw.iam.persistence.model.IamAupSignature;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.persistence.repository.IamAupRepository;
import it.infn.mw.iam.persistence.repository.IamAupSignatureRepository;
import it.infn.mw.iam.test.util.DateEqualModulo1Second;
import it.infn.mw.iam.test.util.MockTimeProvider;
import it.infn.mw.iam.test.util.WithAnonymousUser;
import it.infn.mw.iam.test.util.WithMockOAuthUser;
import it.infn.mw.iam.test.util.annotation.IamMockMvcIntegrationTest;
import it.infn.mw.iam.test.util.oauth.MockOAuth2Filter;

@RunWith(SpringRunner.class)
@IamMockMvcIntegrationTest
@WithAnonymousUser
public class AupSignatureIntegrationTests extends AupTestSupport {

  @Autowired
  private ObjectMapper mapper;

  @Autowired
  private IamAupRepository aupRepo;

  @Autowired
  private IamAupSignatureRepository aupSignatureRepo;

  @Autowired
  private IamAccountService accountService;

  @Autowired
  private IamAccountRepository accountRepo;

  @Autowired
  private MockMvc mvc;

  @Autowired
  private MockOAuth2Filter mockOAuth2Filter;

  @Autowired
  private MockTimeProvider mockTimeProvider;

  private IamAup aup;

  private Date getCurrentDate() {
    return Date.from(Instant.ofEpochMilli(mockTimeProvider.currentTimeMillis()));
  }

  private void initCurrentDate() {
    mockTimeProvider.setTime((new Date()).getTime());
  }

  private void addToCurrentDate(int milliSecs) {
    mockTimeProvider.setTime(DateUtils.addMilliseconds(getCurrentDate(), milliSecs).getTime());
  }

  private Date getCurrentDateAdd(int field, int amount) {
    Calendar calendar = Calendar.getInstance();
    calendar.add(field, amount);
    return calendar.getTime();
  }

  @Before
  public void setup() {
    mockOAuth2Filter.cleanupSecurityContext();
    initCurrentDate();
    aup = buildDefaultAup();
    aupRepo.save(aup);
  }

  @After
  public void cleanupOAuthUser() {
    mockOAuth2Filter.cleanupSecurityContext();
    aupRepo.delete(aup);
  }

  @Test
  public void getAupSignatureRequiresAuthenticatedUser() throws Exception {
    mvc.perform(get("/iam/aup/signature")).andExpect(status().isUnauthorized());
  }

  @Test
  public void signAupSignatureRequiresAuthenticatedUser() throws Exception {
    mvc.perform(post("/iam/aup/signature")).andExpect(status().isUnauthorized());
  }

  @Test
  @WithMockUser(username = "test", roles = {"USER"})
  public void getAupSignatureWithUndefinedAupReturns404() throws Exception {
    aupRepo.deleteAll();
    mvc.perform(get("/iam/aup/signature"))
      .andExpect(status().isNotFound())
      .andExpect(jsonPath("$.error", equalTo("AUP is not defined for this organization")));
  }

  @Test
  @WithMockUser(username = "test", roles = {"USER"})
  public void getAupSignatureWithNoSignatureRecordReturns404() throws Exception {
    mvc.perform(get("/iam/aup/signature"))
      .andExpect(status().isNotFound())
      .andExpect(jsonPath("$.error", equalTo("AUP signature not found for user 'test'")));
  }

  @Test
  @WithMockUser(username = "test", roles = {"USER"})
  public void signatureCreationReturns204() throws Exception {
    mvc.perform(post("/iam/aup/signature")).andExpect(status().isCreated());

    String sigString = mvc.perform(get("/iam/aup/signature"))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.aup").exists())
      .andExpect(jsonPath("$.account.uuid").exists())
      .andExpect(jsonPath("$.account.username", equalTo("test")))
      .andExpect(jsonPath("$.account.name", equalTo("Test User")))
      .andExpect(jsonPath("$.signatureTime").exists())
      .andReturn()
      .getResponse()
      .getContentAsString();

    AupSignatureDTO sig = mapper.readValue(sigString, AupSignatureDTO.class);
    assertThat(sig.getSignatureTime(), new DateEqualModulo1Second(getCurrentDate()));

    addToCurrentDate(1000);
    Date expectedDate = getCurrentDate();

    mvc.perform(post("/iam/aup/signature")).andExpect(status().isCreated());
    sigString = mvc.perform(get("/iam/aup/signature"))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.aup").exists())
      .andExpect(jsonPath("$.account.uuid").exists())
      .andExpect(jsonPath("$.account.username", equalTo("test")))
      .andExpect(jsonPath("$.account.name", equalTo("Test User")))
      .andExpect(jsonPath("$.signatureTime").exists())
      .andReturn()
      .getResponse()
      .getContentAsString();

    sig = mapper.readValue(sigString, AupSignatureDTO.class);
    assertThat(sig.getSignatureTime(), equalTo(expectedDate));
  }

  @Test
  @WithMockUser(username = "admin", roles = {"ADMIN", "USER"})
  public void signatureOnBehalfWithoutRequestBodyWorksWhenUserHasNoSignature()
      throws Exception, NoSuchElementException {

    IamAccount testAccount = accountRepo.findByUsername("test").orElseThrow();

    Optional<IamAupSignature> signature =
        aupSignatureRepo.findSignatureForAccount(aup, testAccount);
    assertThat(signature.isPresent(), equalTo(false));

    mvc.perform(patch("/iam/aup/signature/{accountId}", testAccount.getUuid()))
      .andExpect(status().isCreated());

    assertThat(aupSignatureRepo.findSignatureForAccount(aup, testAccount).isPresent(),
        equalTo(true));

    AupSignatureDTO responseDTO =
        mapper.readValue(mvc.perform(get("/iam/aup/signature/{accountId}", testAccount.getUuid()))
          .andExpect(status().isOk())
          .andExpect(jsonPath("$.aup").exists())
          .andExpect(jsonPath("$.account.uuid").exists())
          .andExpect(jsonPath("$.account.uuid", equalTo(testAccount.getUuid())))
          .andExpect(jsonPath("$.account.username", equalTo(testAccount.getUsername())))
          .andExpect(jsonPath("$.account.name", equalTo(testAccount.getUserInfo().getName())))
          .andExpect(jsonPath("$.signatureTime").exists())
          .andReturn()
          .getResponse()
          .getContentAsString(), AupSignatureDTO.class);

    assertThat(responseDTO.getSignatureTime(), equalTo(getCurrentDate()));
  }

  @Test
  @WithMockUser(username = "admin", roles = {"ADMIN", "USER"})
  public void signatureOnBehalfWithRequestBodyWorksWhenUserHasNoSignature()
      throws Exception, NoSuchElementException {

    IamAccount testAccount = accountRepo.findByUsername("test").orElseThrow();

    Optional<IamAupSignature> signature =
        aupSignatureRepo.findSignatureForAccount(aup, testAccount);
    assertThat(signature.isPresent(), equalTo(false));

    Date updatedSignature = getCurrentDateAdd(Calendar.HOUR, 2);
    AupSignaturePatchRequestDTO dto = new AupSignaturePatchRequestDTO();
    dto.setSignatureTime(updatedSignature);

    mvc.perform(patch("/iam/aup/signature/{accountId}", testAccount.getUuid())
      .content(mapper.writeValueAsString(dto))
      .contentType(APPLICATION_JSON)).andExpect(status().isCreated());

    assertThat(aupSignatureRepo.findSignatureForAccount(aup, testAccount).isPresent(),
        equalTo(true));

    AupSignatureDTO responseDTO =
        mapper.readValue(mvc.perform(get("/iam/aup/signature/{accountId}", testAccount.getUuid()))
          .andExpect(status().isOk())
          .andExpect(jsonPath("$.aup").exists())
          .andExpect(jsonPath("$.account.uuid").exists())
          .andExpect(jsonPath("$.account.uuid", equalTo(testAccount.getUuid())))
          .andExpect(jsonPath("$.account.username", equalTo(testAccount.getUsername())))
          .andExpect(jsonPath("$.account.name", equalTo(testAccount.getUserInfo().getName())))
          .andExpect(jsonPath("$.signatureTime").exists())
          .andReturn()
          .getResponse()
          .getContentAsString(), AupSignatureDTO.class);

    assertThat(responseDTO.getSignatureTime(), equalTo(updatedSignature));
  }

  @Test
  @WithMockOAuthUser(scopes = "iam:admin.write", clientId = "client-cred")
  public void signatureOnBehalfWithClientCredentialsWorks()
      throws Exception, NoSuchElementException {

    IamAccount testAccount = accountRepo.findByUsername("test").orElseThrow();

    Optional<IamAupSignature> signature =
        aupSignatureRepo.findSignatureForAccount(aup, testAccount);
    assertThat(signature.isPresent(), equalTo(false));

    mvc.perform(patch("/iam/aup/signature/{accountId}", testAccount.getUuid()))
      .andExpect(status().isCreated());

    signature = aupSignatureRepo.findSignatureForAccount(aup, testAccount);
    assertThat(signature.isPresent(), equalTo(true));

    aupSignatureRepo.deleteById(signature.get().getId());

    AupSignaturePatchRequestDTO dto = new AupSignaturePatchRequestDTO();
    dto.setSignatureTime(getCurrentDate());

    mvc.perform(patch("/iam/aup/signature/{accountId}", testAccount.getUuid())
      .content(mapper.writeValueAsString(dto))
      .contentType(APPLICATION_JSON)).andExpect(status().isCreated());

    assertThat(aupSignatureRepo.findSignatureForAccount(aup, testAccount).isPresent(),
        equalTo(true));

  }

  @Test
  @WithMockUser(username = "admin", roles = {"ADMIN", "USER"})
  public void aupRemovalForSingleUser() throws Exception {

    mvc.perform(post("/iam/aup/signature")).andExpect(status().isCreated());

    IamAccount account = accountRepo.findByUsername("admin")
      .orElseThrow(() -> new AssertionError("Expected admin account not found"));

    mvc.perform(delete("/iam/aup/signature/" + account.getUuid()))
      .andExpect(status().isNoContent());
    mvc.perform(delete("/iam/aup/signature/" + account.getUuid()))
      .andExpect(status().isNoContent());
    mvc.perform(get("/iam/aup/signature/" + account.getUuid()))
      .andExpect(status().isNotFound())
      .andExpect(jsonPath("$.error", equalTo("AUP signature not found for user 'admin'")));

  }

  @Test
  @WithMockOAuthUser(scopes = "iam:admin.write", clientId = "client-cred")
  public void aupRemovalForSingleUserWithClientCredentialsWorks() throws Exception {

    IamAccount testAccount = accountRepo.findByUsername("test").orElseThrow();

    Optional<IamAupSignature> signature = aupSignatureRepo.findSignatureForAccount(aup, testAccount);
    assertThat(signature.isPresent(), equalTo(false));
    aupSignatureRepo.createSignatureForAccount(aup, testAccount, getCurrentDate());

    mvc.perform(delete("/iam/aup/signature/" + testAccount.getUuid()))
      .andExpect(status().isNoContent());

    signature = aupSignatureRepo.findSignatureForAccount(aup, testAccount);
    assertThat(signature.isPresent(), equalTo(false));
  }

  @Test
  @WithMockUser(username = "admin", roles = {"ADMIN", "USER"})
  public void aupRemovalRemovesSignatureRecords() throws Exception {

    mvc.perform(post("/iam/aup/signature")).andExpect(status().isCreated());
    mvc.perform(delete("/iam/aup")).andExpect(status().isNoContent());

    IamAccount adminAccount = accountRepo.findByUsername("admin").orElseThrow();
    Optional<IamAupSignature> signature =
        aupSignatureRepo.findSignatureForAccount(aup, adminAccount);
    assertThat(signature.isEmpty(), equalTo(true));

    mvc.perform(get("/iam/aup/signature"))
      .andExpect(status().isNotFound())
      .andExpect(jsonPath("$.error", equalTo("AUP is not defined for this organization")));
  }

  @Test
  @WithMockUser(username = "admin", roles = {"ADMIN", "USER"})
  public void accountRemovalRemovesSignatureRecords() throws Exception {

    mvc.perform(post("/iam/aup/signature")).andExpect(status().isCreated());

    IamAccount account = accountRepo.findByUsername("admin")
      .orElseThrow(() -> new AssertionError("Expected admin account not found"));

    accountService.deleteAccount(account);
  }

  @Test
  @WithMockUser(username = "test", roles = {"USER"})
  public void normalUserCannotSeeOtherUserAup() throws Exception {

    mvc.perform(post("/iam/aup/signature")).andExpect(status().isCreated());
    mvc.perform(get("/iam/aup/signature")).andExpect(status().isOk());
    mvc.perform(get("/iam/aup/signature/" + TEST_USER_UUID)).andExpect(status().isOk());
    mvc.perform(get("/iam/aup/signature/" + TEST_100_USER_UUID)).andExpect(status().isForbidden());
  }

  @Test
  public void adminUserCanSeeOtherUserAup() throws Exception {

    mvc.perform(post("/iam/aup/signature").with(user("test").roles("USER")))
      .andExpect(status().isCreated());
    mvc.perform(get("/iam/aup/signature").with(user("test").roles("USER")))
      .andExpect(status().isOk());
    mvc.perform(get("/iam/aup/signature/" + TEST_USER_UUID).with(user("test").roles("USER")))
      .andExpect(status().isOk());
    mvc.perform(get("/iam/aup/signature/" + TEST_USER_UUID).with(user("test_100").roles("READER")))
      .andExpect(status().isOk());
    mvc
      .perform(
          get("/iam/aup/signature/" + TEST_USER_UUID).with(user("admin").roles("USER", "ADMIN")))
      .andExpect(status().isOk());
  }

  @Test
  @WithMockUser(username = "admin", roles = {"USER", "ADMIN"})
  public void signAupOnBehalfOfUserThatHasAlreadyASignature() throws Exception {

    IamAccount testAccount = accountRepo.findByUsername("test").orElseThrow();
    IamAupSignature signature =
        aupSignatureRepo.createSignatureForAccount(aup, testAccount, getCurrentDate());

    // patch with no body => set signature to current Date
    AupSignatureDTO signatureResponse =
        mapper.readValue(mvc.perform(patch("/iam/aup/signature/{accountId}", TEST_USER_UUID))
          .andExpect(CREATED)
          .andReturn()
          .getResponse()
          .getContentAsString(), AupSignatureDTO.class);

    assertThat(signatureResponse.getSignatureTime().compareTo(signature.getSignatureTime()), is(0));

    AupSignatureDTO dto = new AupSignatureDTO();
    Calendar calendar = Calendar.getInstance();
    calendar.add(Calendar.HOUR, 2);
    dto.setSignatureTime(calendar.getTime());

    AupSignatureDTO updatedSignature = mapper.readValue(mvc
      .perform(patch("/iam/aup/signature/{accountId}", TEST_USER_UUID)
        .content(mapper.writeValueAsString(dto))
        .contentType(APPLICATION_JSON))
      .andExpect(CREATED)
      .andReturn()
      .getResponse()
      .getContentAsString(), AupSignatureDTO.class);

    assertThat(updatedSignature.getSignatureTime().compareTo(dto.getSignatureTime()), is(0));
  }

  @Test
  @WithMockUser(username = "admin", roles = {"USER", "ADMIN"})
  public void signAupOnBehalfOfUserThatHasNoSignature() throws Exception {

    mvc.perform(get("/iam/aup/signature/{accountId}", TEST_USER_UUID))
      .andExpect(status().isNotFound())
      .andExpect(jsonPath("$.error", equalTo("AUP signature not found for user 'test'")));

    mvc.perform(patch("/iam/aup/signature/{accountId}", TEST_USER_UUID)).andExpect(CREATED);

    mvc.perform(get("/iam/aup/signature/{accountId}", TEST_USER_UUID))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.aup").exists())
      .andExpect(jsonPath("$.account.uuid").exists())
      .andExpect(jsonPath("$.account.username", equalTo("test")))
      .andExpect(jsonPath("$.account.name", equalTo("Test User")))
      .andExpect(jsonPath("$.signatureTime").exists());

    mvc.perform(get("/iam/aup/signature/{accountId}", TEST_USER_UUID)).andExpect(status().isOk());

  }

  @Test
  @WithMockUser(username = "test", roles = {"USER"})
  public void testSignAupThrowExceptionForServiceAccount() throws Exception {
       
    IamAccount testAccount = accountRepo.findByUsername("test").orElseThrow();
    testAccount.setServiceAccount(true);
    accountRepo.save(testAccount);

    mvc.perform(post("/iam/aup/sign"))
    .andExpect(status().isMethodNotAllowed());
  }

}
