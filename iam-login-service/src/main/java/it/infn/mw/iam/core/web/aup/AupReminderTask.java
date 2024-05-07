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
package it.infn.mw.iam.core.web.aup;

import java.time.LocalDate;
import java.time.ZoneId;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import it.infn.mw.iam.notification.NotificationFactory;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamAupSignature;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.persistence.repository.IamAupRepository;

@Component
public class AupReminderTask implements Runnable {

  @Autowired
  IamAccountRepository accounts;

  @Autowired
  IamAupRepository aupRepo;

  @Autowired
  NotificationFactory notification;

  public void sendAupReminders() {
    aupRepo.findDefaultAup().ifPresent(aup -> {
      LocalDate now = LocalDate.now();
      List<Integer> intervals = Arrays.stream(aup.getAupRemindersInDays().split(","))
        .map(Integer::valueOf)
        .collect(Collectors.toList());

      for (IamAccount account : accounts.findAll()) {
        IamAupSignature signature = account.getAupSignature();
        if (signature != null && signature.getSignatureTime() != null) {
          LocalDate signatureTime =
              signature.getSignatureTime().toInstant().atZone(ZoneId.systemDefault()).toLocalDate();
          long signatureValidityInDays = aup.getSignatureValidityInDays();
          LocalDate signatureValidTime = signatureTime.plusDays(signatureValidityInDays);

          long daysUntilExpiration = ChronoUnit.DAYS.between(now, signatureValidTime);
          if (daysUntilExpiration >= 0 && intervals.contains((int) daysUntilExpiration)) {
            notification.createAupReminderMessage(account, aup);
          }
        }
      }
    });
  }


  @Override
  public void run() {
    sendAupReminders();
  }

}
