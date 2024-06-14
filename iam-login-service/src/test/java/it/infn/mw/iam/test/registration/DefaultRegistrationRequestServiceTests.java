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
package it.infn.mw.iam.test.registration;

import static org.junit.Assert.assertTrue;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.mockito.Spy;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit4.SpringRunner;

import it.infn.mw.iam.config.IamProperties.ExternalAuthAttributeSectionBehaviour;
import it.infn.mw.iam.config.IamProperties.RegistrationFieldProperties;
import it.infn.mw.iam.core.IamRegistrationRequestStatus;
import it.infn.mw.iam.persistence.model.IamRegistrationRequest;
import it.infn.mw.iam.persistence.repository.IamRegistrationRequestRepository;
import it.infn.mw.iam.registration.DefaultRegistrationRequestService;
import it.infn.mw.iam.registration.RegistrationRequestDto;
import it.infn.mw.iam.registration.validation.RegistrationRequestValidatorError;
import it.infn.mw.iam.api.scim.exception.ScimResourceNotFoundException;
import it.infn.mw.iam.api.scim.exception.IllegalArgumentException;

@RunWith(SpringRunner.class)
@SpringBootTest
public class DefaultRegistrationRequestServiceTests {

    @InjectMocks
    @Spy
    private DefaultRegistrationRequestService service;

    @Mock
    private IamRegistrationRequestRepository iamRegistrationRequestRepository;

    @Before
    public void init() {
        MockitoAnnotations.openMocks(this);
    }

    @Test
    public void testCreateRequestWithNotesBeingMandatoryField() {
        String username = "user_with_empty_notes";
        String email = username + "@example.org";

        RegistrationRequestDto request = new RegistrationRequestDto();
        request.setGivenname("Test");
        request.setFamilyname("User");
        request.setEmail(email);
        request.setUsername(username);
        request.setPassword("password");

        Map<String, RegistrationFieldProperties> fieldAttribute = new HashMap<>();
        RegistrationFieldProperties notesProperties = new RegistrationFieldProperties();
        notesProperties.setFieldBehaviour(ExternalAuthAttributeSectionBehaviour.MANDATORY);
        fieldAttribute.put("notes", notesProperties);

        Exception exception = assertThrows(RegistrationRequestValidatorError.class, () -> {
            service.createRequest(request, Optional.empty(), fieldAttribute);
        });

        assertTrue(exception.getMessage().contains("Notes field cannot be null"));
    }

    @Test
    public void testCreateRequestWithNotesBeingMandatoryBlankData() {
        String username = "user_with_empty_notes";
        String email = username + "@example.org";

        RegistrationRequestDto request = new RegistrationRequestDto();
        request.setGivenname("Test");
        request.setFamilyname("User");
        request.setEmail(email);
        request.setUsername(username);
        request.setNotes("   ");
        request.setPassword("password");

        Map<String, RegistrationFieldProperties> fieldAttribute = new HashMap<>();
        RegistrationFieldProperties notesProperties = new RegistrationFieldProperties();
        notesProperties.setReadOnly(true);
        notesProperties.setExternalAuthAttribute("notes");
        notesProperties.setFieldBehaviour(ExternalAuthAttributeSectionBehaviour.MANDATORY);
        fieldAttribute.put("notes", notesProperties);

        Exception exception = assertThrows(RegistrationRequestValidatorError.class, () -> {
            service.createRequest(request, Optional.empty(), fieldAttribute);
        });

        assertEquals(true, fieldAttribute.get("notes").isReadOnly());
        assertEquals("notes", fieldAttribute.get("notes").getExternalAuthAttribute());
        assertTrue(exception.getMessage().contains("Notes field cannot be the empty string"));
    }

    @Test
    public void testRejectRequestException() {
        String requestUuid = "some-uuid";
        IamRegistrationRequest request = new IamRegistrationRequest();

        // ONLY used `status` because it is being used in `rejectRequest`.
        request.setStatus(IamRegistrationRequestStatus.APPROVED);

        when(iamRegistrationRequestRepository.findByUuid(requestUuid)).thenReturn(Optional.of(request));

        Exception exception = assertThrows(IllegalArgumentException.class, () -> {
            service.rejectRequest(requestUuid, Optional.of("Rejected"));
        });

        assertTrue(exception.getMessage().contains("Bad status transition from"));
        verify(iamRegistrationRequestRepository, times(0)).save(any());
    }

    @Test
    public void testListRequestsStatusNotFound() {
        IamRegistrationRequestStatus status = IamRegistrationRequestStatus.NEW;
        when(iamRegistrationRequestRepository.findByStatus(status)).thenReturn(Optional.empty());

        Exception exception = assertThrows(IllegalStateException.class, () -> {
            service.listRequests(status);
        });

        assertTrue(exception.getMessage().contains("No request found with status: " + status.name()));
    }

    @Test
    public void testRejectRequestWithNoValidUUID() {
        String requestWithNoUUID = "no-id";

        when(iamRegistrationRequestRepository.findByUuid(requestWithNoUUID)).thenReturn(Optional.empty());

        Exception exception = assertThrows(ScimResourceNotFoundException.class, () -> {
            service.rejectRequest(requestWithNoUUID, Optional.of("No ID"));
        });

        assertTrue(exception.getMessage().contains("No request mapped to uuid"));
    }
}