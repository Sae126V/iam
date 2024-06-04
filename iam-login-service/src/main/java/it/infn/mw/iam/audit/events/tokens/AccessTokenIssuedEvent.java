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
package it.infn.mw.iam.audit.events.tokens;

import java.text.ParseException;
import java.util.Map;

import org.mitre.oauth2.model.OAuth2AccessTokenEntity;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.collect.Maps;
import com.nimbusds.jose.JWSHeader;

import it.infn.mw.iam.audit.events.IamAuditApplicationEvent;
import it.infn.mw.iam.audit.events.IamEventCategory;


public class AccessTokenIssuedEvent extends IamAuditApplicationEvent {

  private static final long serialVersionUID = 1L;

  public static final Logger LOG = LoggerFactory.getLogger(AccessTokenIssuedEvent.class);

  private final HeaderDTO header = new HeaderDTO();
  private final transient Map<String, Object> body;


  public AccessTokenIssuedEvent(Object source, OAuth2AccessTokenEntity token) {
    super(IamEventCategory.TOKEN, source, "Access token issued");

    Map<String, Object> parsedTokenMap = Maps.newHashMap();
    try {
      parsedTokenMap = token.getJwt().getJWTClaimsSet().getClaims();
    } catch (ParseException e) {
      LOG.warn(e.getMessage(), e);
    }
    this.body = parsedTokenMap;

    this.header.setAlg(token.getJwt().getHeader().getAlgorithm().getName());
    this.header.setKid(String.valueOf(((JWSHeader) token.getJwt().getHeader()).getKeyID()));
  }

  public Map<String, Object> getBody() {
    return body;
  }

  public HeaderDTO getHeader() {
    return header;
  }
}
