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

import javax.validation.Valid;

import javax.validation.constraints.NotEmpty;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Sort;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import it.infn.mw.iam.api.common.ListResponseDTO;
import it.infn.mw.iam.api.common.OffsetPageable;
import it.infn.mw.iam.api.common.PagingUtils;
import it.infn.mw.iam.api.requests.model.CertLinkRequestDto;
import it.infn.mw.iam.api.requests.service.CertLinkRequestsService;

@RestController
@RequestMapping("/iam/cert_link_requests")
@Validated
public class CertLinkRequestsController {

  private static final Integer CERT_LINK_REQUEST_MAX_PAGE_SIZE = 10;

  @Autowired
  private CertLinkRequestsService certLinkRequestService;

  @RequestMapping(method = RequestMethod.POST, value = { "", "/" })
  @PreAuthorize("hasAnyRole('ADMIN', 'USER')")
  public CertLinkRequestDto createCertLinkRequest(@RequestBody @Valid CertLinkRequestDto certLinkRequest) {
    return certLinkRequestService.createCertLinkRequest(certLinkRequest);
  }

  @RequestMapping(method = RequestMethod.GET, value = { "", "/" })
  @PreAuthorize("hasAnyRole('ADMIN','USER')")
  public ListResponseDTO<CertLinkRequestDto> listCertLinkRequest(
      @RequestParam(required = false) String username,
      @RequestParam(required = false) String subject,
      @RequestParam(required = false) String status,
      @RequestParam(required = false) Integer count,
      @RequestParam(required = false) Integer startIndex) {

    final Sort sort = Sort.by("account.username", "certificate.subjectDn", "creationTime");

    OffsetPageable pageRequest = PagingUtils.buildPageRequest(count, startIndex, CERT_LINK_REQUEST_MAX_PAGE_SIZE, sort);

    return certLinkRequestService.listCertLinkRequests(username, subject, status, pageRequest);
  }

  @RequestMapping(method = RequestMethod.GET, value = "/{requestId}")
  @PreAuthorize("hasScope('iam:admin:read')")
  public CertLinkRequestDto getCertLinkRequestDetails(
      @Valid @PathVariable("requestId") String requestId) {
    return certLinkRequestService.getCertLinkRequestDetails(requestId);
  }

  @RequestMapping(method = RequestMethod.DELETE, value = "/{requestId}")
  @PreAuthorize("hasScope('iam:admin:write')")
  @ResponseStatus(HttpStatus.NO_CONTENT)
  public void deleteCertLinkRequest(@Valid @PathVariable("requestId") String requestId) {
    certLinkRequestService.deleteCertLinkRequest(requestId);
  }

  @RequestMapping(method = RequestMethod.POST, value = "/{requestId}/approve")
  @PreAuthorize("hasScope('iam:admin:write')")
  @ResponseStatus(HttpStatus.OK)
  public CertLinkRequestDto approveCertLinkRequest(@Valid @PathVariable("requestId") String requestId) {
    return certLinkRequestService.approveCertLinkRequest(requestId);
  }

  @RequestMapping(method = RequestMethod.POST, value = "/{requestId}/reject")
  @PreAuthorize("hasScope('iam:admin:write')")
  @ResponseStatus(HttpStatus.OK)
  public CertLinkRequestDto rejectCertLinkRequest(@Valid @PathVariable("requestId") String requestId,
      @RequestParam @NotEmpty String motivation) {
    return certLinkRequestService.rejectCertLinkRequest(requestId, motivation);
  }

}