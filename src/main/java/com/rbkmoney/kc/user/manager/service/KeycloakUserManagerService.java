package com.rbkmoney.kc.user.manager.service;

import com.rbkmoney.kc.user.manager.mapper.UserRepresentationMapper;
import com.rbkmoney.kc.user.manager.keycloak.KeycloakAdminClientManager;
import com.rbkmoney.kc.user.manager.model.UserActions;
import com.rbkmoney.kc_user_manager.CreateUserResponse;
import com.rbkmoney.kc_user_manager.EmailSendingRequest;
import com.rbkmoney.kc_user_manager.KeycloakUserManagerException;
import com.rbkmoney.kc_user_manager.KeycloakUserManagerSrv;
import com.rbkmoney.kc_user_manager.Status;
import com.rbkmoney.kc_user_manager.SuccessfulUserCreation;
import com.rbkmoney.kc_user_manager.User;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.thrift.TException;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.representations.idm.UserRepresentation;
import org.springframework.stereotype.Service;

import javax.ws.rs.core.Response;
import java.util.Collections;
import java.util.List;

@Slf4j
@RequiredArgsConstructor
@Service
public class KeycloakUserManagerService implements KeycloakUserManagerSrv.Iface {

    private final KeycloakAdminClientManager keycloakAdminClientManager;

    @Override
    public CreateUserResponse create(User user) throws TException {
        log.info("Create user {} in keycloak", user);
        Keycloak adminClient = keycloakAdminClientManager.getKcClient(user.getUserId().getRealm());
        adminClient.tokenManager().getAccessToken();
        Response response = adminClient
                .realm(user.getUserId().getRealm())
                .users()
                .create(UserRepresentationMapper.map(user));

        if (response.getStatus() != 201) {
            throw new KeycloakUserManagerException().setReason(
                    String.format("Error: HTTP code - %s, reason - %s",
                            response.getStatus(), response.getStatusInfo().getReasonPhrase())
            );
        }

        String keycloakUserId = response.getLocation().toString();
        SuccessfulUserCreation userCreation = new SuccessfulUserCreation(keycloakUserId);

        log.info("Created user {} in keycloak with id {}", user.getUserId(), keycloakUserId);
        return new CreateUserResponse(Status.success(userCreation));
    }

    @Override
    public void sendUpdatePasswordEmail(EmailSendingRequest emailRequest) throws TException {
        executeActionsEmail(emailRequest, UserActions.UPDATE_PASSWORD);
    }

    @Override
    public void sendVerifyUserEmail(EmailSendingRequest emailRequest) throws TException {
        executeActionsEmail(emailRequest, UserActions.VERIFY_EMAIL);
    }

    private void executeActionsEmail(EmailSendingRequest emailRequest, UserActions action)
            throws KeycloakUserManagerException {
        log.info("Execute user email action {}. EmailRequest {}", action, emailRequest);
        Keycloak adminClient = keycloakAdminClientManager.getKcClient(emailRequest.getUserId().getRealm());
        adminClient.tokenManager().getAccessToken();
        RealmResource realmResource = adminClient.realm(emailRequest.getUserId().getRealm());

        UserRepresentation user = findUserByEmail(emailRequest.getUserId().getEmail(), realmResource);

        realmResource
                .users()
                .get(user.getId())
                .executeActionsEmail(
                        emailRequest.isSetRedirectParams()
                                ? emailRequest.getRedirectParams().getClientId()
                                : null,
                        emailRequest.isSetRedirectParams()
                                ? emailRequest.getRedirectParams().getRedirectUri()
                                : null,
                        Collections.singletonList(action.name())
                );
        log.info("Action {} executed for user {}", action, emailRequest.getUserId());
    }

    /**
     * Finds user in keycloak by username.
     * @param email user's email
     * @param realmResource realm resource
     * @return brief representation of user
     * @throws KeycloakUserManagerException if user not found
     */
    private UserRepresentation findUserByEmail(String email, RealmResource realmResource)
            throws KeycloakUserManagerException {
        List<UserRepresentation> searchResults = realmResource
                .users()
                .search(
                        null,
                        null,
                        null,
                        email,
                        null,
                        null,
                        true
                );

        if (searchResults.isEmpty()) {
            throw new KeycloakUserManagerException().setReason(String.format("user with email %s not found", email));
        }

        return searchResults.stream()
                .filter(user -> email.equals(user.getEmail()))
                .findAny()
                .orElseThrow(() -> new KeycloakUserManagerException()
                        .setReason(String.format("user with email %s not found", email)));
    }

}
