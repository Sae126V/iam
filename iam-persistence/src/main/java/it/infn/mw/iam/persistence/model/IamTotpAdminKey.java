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
package it.infn.mw.iam.persistence.model;

import javax.persistence.Entity;

import javax.persistence.TemporalType;

import java.io.Serializable;
import java.util.Date;

import javax.persistence.Column;
import javax.persistence.Id;
import javax.persistence.Table;
import javax.persistence.Temporal;

@Entity
@Table(name = "iam_totp_admin_key")
public class IamTotpAdminKey implements Serializable {

  /**
   * 
   */
  private static final long serialVersionUID = 1L;

  @Id
  private Long id = 1L;

  @Column(name = "admin_mfa_key", nullable = false)
  private String adminMFAKey;

  @Temporal(TemporalType.TIMESTAMP)
  @Column(name = "last_update_time", nullable = false)
  private Date lastUpdateTime;

  public IamTotpAdminKey() {}

  public IamTotpAdminKey(String adminMFAKey) {
    Date now = new Date();

    this.id = 1L;
    this.adminMFAKey = adminMFAKey;
    setLastUpdateTime(now);
  }

  // getters and setters
  public Long getId() {
    return id;
  }

  public void setId(Long id) {
    this.id = id;
  }

  public Date getLastUpdateTime() {
    return lastUpdateTime;
  }

  public void setLastUpdateTime(Date lastUpdateTime) {
    this.lastUpdateTime = lastUpdateTime;
  }

  public String getAdminMFAKey() {
    return adminMFAKey;
  }

  public void setAdminMFAKey(String adminMFAKey) {
    this.adminMFAKey = adminMFAKey;
  }

  @Override
  public String toString() {
    return "IamTotpAdminKey [id=" + id + ", adminMFAKey=" + adminMFAKey + ", lastUpdateTime=" + lastUpdateTime + "]";
  }

  @Override
  public int hashCode() {
    final int prime = 31;
    int result = 1;
    result = prime * result + ((adminMFAKey == null) ? 0 : adminMFAKey.hashCode());
    return result;
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj)
      return true;
    if (obj == null)
      return false;
    if (getClass() != obj.getClass())
      return false;
    IamTotpAdminKey other = (IamTotpAdminKey) obj;
    if (adminMFAKey == null) {
      if (other.adminMFAKey != null)
        return false;
    } else if (!adminMFAKey.equals(other.adminMFAKey))
      return false;
    return true;
  }
}
