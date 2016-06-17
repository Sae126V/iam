package it.infn.mw.iam.api.scim.converter;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import it.infn.mw.iam.api.scim.model.ScimEmail;
import it.infn.mw.iam.api.scim.model.ScimGroupRef;
import it.infn.mw.iam.api.scim.model.ScimIndigoUser;
import it.infn.mw.iam.api.scim.model.ScimMeta;
import it.infn.mw.iam.api.scim.model.ScimName;
import it.infn.mw.iam.api.scim.model.ScimOidcId;
import it.infn.mw.iam.api.scim.model.ScimUser;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamGroup;
import it.infn.mw.iam.persistence.model.IamOidcId;
import it.infn.mw.iam.persistence.model.IamUserInfo;

@Service
public class UserConverter implements Converter<ScimUser, IamAccount> {

  private final ScimResourceLocationProvider resourceLocationProvider;

  private final AddressConverter addressConverter;

  @Autowired
  public UserConverter(ScimResourceLocationProvider rlp, AddressConverter ac) {
    this.resourceLocationProvider = rlp;
    this.addressConverter = ac;
  }

  @Override
  public IamAccount fromScim(ScimUser scimUser) {

    IamAccount account = new IamAccount();
    IamUserInfo userInfo = new IamUserInfo();

    account.setUuid(scimUser.getId());

    if (scimUser.getActive() != null) {
      account.setActive(scimUser.getActive());
    }

    account.setUsername(scimUser.getUserName());

    userInfo.setEmail(scimUser.getEmails().get(0).getValue());
    userInfo.setGivenName(scimUser.getName().getGivenName());
    userInfo.setFamilyName(scimUser.getName().getFamilyName());
    userInfo.setMiddleName(scimUser.getName().getMiddleName());
    userInfo.setName(scimUser.getName().getFormatted());

    account.setUserInfo(userInfo);

    if (scimUser.getAddresses() != null && scimUser.getAddresses().size() > 0) {

      userInfo.setAddress(addressConverter.fromScim(scimUser.getAddresses().get(0)));

    }

    return account;

  }

  @Override
  public ScimUser toScim(IamAccount entity) {

    ScimMeta.Builder metaBuilder =
        new ScimMeta.Builder(entity.getCreationTime(), entity.getLastUpdateTime())
            .location(resourceLocationProvider.userLocation(entity.getUuid()))
            .resourceType(ScimUser.RESOURCE_TYPE);

    ScimName.Builder nameBuilder =
        new ScimName.Builder().givenName(entity.getUserInfo().getGivenName())
            .familyName(entity.getUserInfo().getFamilyName())
            .middleName(entity.getUserInfo().getMiddleName());

    ScimIndigoUser.Builder indigoUserBuilder = new ScimIndigoUser.Builder();

    for (IamOidcId oidcId : entity.getOidcIds()) {
      ScimOidcId scimOidcid =
          new ScimOidcId.Builder().issuer(oidcId.getIssuer()).subject(oidcId.getSubject()).build();

      indigoUserBuilder.addOidcid(scimOidcid);

    }

    ScimEmail email = ScimEmail.builder().email(entity.getUserInfo().getEmail()).build();

    ScimIndigoUser indigoUser = indigoUserBuilder.build();

    if (indigoUser.getOidcIds().isEmpty() && indigoUser.getSamlIds().isEmpty()
        && indigoUser.getSshKeys().isEmpty()) {
      indigoUser = null;
    }

    ScimUser.Builder builder = new ScimUser.Builder(entity.getUsername()).id(entity.getUuid())
        .meta(metaBuilder.build()).name(nameBuilder.build()).active(entity.isActive())
        .displayName(entity.getUsername()).locale(entity.getUserInfo().getLocale())
        .nickName(entity.getUserInfo().getNickname()).profileUrl(entity.getUserInfo().getProfile())
        .timezone(entity.getUserInfo().getZoneinfo()).addEmail(email).indigoUserInfo(indigoUser);

    if (entity.getUserInfo().getAddress() != null) {

      builder.addAddress(addressConverter.toScim(entity.getUserInfo().getAddress()));
    }

    for (IamGroup group : entity.getGroups()) {
      ScimGroupRef groupRef =
          new ScimGroupRef.Builder().value(group.getUuid()).display(group.getName())
              .ref(resourceLocationProvider.groupLocation(group.getUuid())).build();

      builder.addGroup(groupRef);
    }

    return builder.build();
  }

}