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
package it.infn.mw.iam.api.requests;

import static it.infn.mw.iam.core.IamRequestStatus.PENDING;
import static java.lang.String.format;

import java.util.List;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import com.google.common.base.Strings;

import it.infn.mw.iam.api.requests.exception.IamRequestValidationError;
import it.infn.mw.iam.api.requests.model.CertLinkRequestDto;
import it.infn.mw.iam.authn.error.AccountAlreadyLinkedError;
import it.infn.mw.iam.core.IamRequestStatus;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamCertLinkRequest;
import it.infn.mw.iam.persistence.model.IamX509Certificate;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.persistence.repository.IamCertLinkRequestRepository;

@Component
public class CertLinkRequestUtils {

  @Autowired
  private IamCertLinkRequestRepository certLinkRequestRepository;

  @Autowired
  private IamAccountRepository accountRepository;

  public Optional<IamCertLinkRequest> getOptionalCertLinkRequest(String uuid) {
    return certLinkRequestRepository.findByUuid(uuid);
  }

  public IamCertLinkRequest getCertLinkRequest(String requestId) {
    return certLinkRequestRepository.findByUuid(requestId)
        .orElseThrow(() -> new IamRequestValidationError(
            String.format("CertLink request with UUID [%s] does not exist", requestId)));
  }

  public void checkRequestAlreadyExist(CertLinkRequestDto requestDto) {

    List<IamCertLinkRequest> results = certLinkRequestRepository
        .findByAccountAndDns(requestDto.getUserUuid(), requestDto.getSubjectDn(), requestDto.getIssuerDn());

    for (IamCertLinkRequest r : results) {
      IamRequestStatus status = r.getStatus();

      if (PENDING.equals(status)) {
        throw new IamRequestValidationError(
            String.format("CertLink request already exists for [%s | %s | %s]",
                requestDto.getUsername(), requestDto.getSubjectDn(), requestDto.getIssuerDn()));
      }
    }
  }

  public void validateRejectMotivation(String motivation) {
    String value = motivation;
    if (motivation != null) {
      value = motivation.trim();
    }

    if (Strings.isNullOrEmpty(value)) {
      throw new IamRequestValidationError("Reject motivation cannot be empty");
    }
  }

  public void checkCertAlreadyLinked(CertLinkRequestDto requestDto, IamAccount userAccount) {
    Optional<IamX509Certificate> linkedCerts = userAccount.getX509Certificates()
        .stream()
        .filter(
            c -> c.getSubjectDn().equals(requestDto.getSubjectDn()) && c.getIssuerDn().equals(requestDto.getIssuerDn()))
        .findAny();

    if (linkedCerts.isPresent()) {
      throw new IamRequestValidationError(
          String.format("User [%s] is already linekd to the certificate [%s | %s]", requestDto.getUsername(),
              requestDto.getSubjectDn(), requestDto.getIssuerDn()));
    }
  }

  public void checkCertNotLinkedToSomeoneElse(CertLinkRequestDto request, IamAccount userAccount) {
    accountRepository.findByCertificateSubject(request.getSubjectDn()).ifPresent(linkedAccount -> {
      if (!linkedAccount.getUuid().equals(userAccount.getUuid())) {
        throw new AccountAlreadyLinkedError(
            format("X.509 credential with subject '%s' is already linked to another user",
                request.getSubjectDn()));
      }
    });
  }
}