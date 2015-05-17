package be.c4j.ee.security.credentials.authentication.oauth2.info;

import be.c4j.ee.security.credentials.authentication.oauth2.OAuth2ProviderMetaData;
import be.c4j.ee.security.credentials.authentication.oauth2.OAuth2User;
import org.apache.deltaspike.core.api.provider.BeanProvider;
import org.scribe.model.Token;

import javax.annotation.PostConstruct;
import javax.inject.Inject;
import javax.inject.Singleton;
import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.GET;
import javax.ws.rs.HeaderParam;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import java.util.Iterator;
import java.util.List;

/**
 *
 */
@Path("/info")
@Singleton
public class UserController {

    private List<OAuth2ProviderMetaData> oAuth2ProviderMetaDataList;

    @Inject
    private ExternalInternalIdMapper externalInternalIdMapper;

    @PostConstruct
    public void init() {
        oAuth2ProviderMetaDataList = BeanProvider.getContextualReferences(OAuth2ProviderMetaData.class, false);
    }

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    public OAuth2User getUserInfo(@HeaderParam("token") String token, @HeaderParam("provider") String provider, @Context HttpServletRequest req) {
        OAuth2InfoProvider infoProvider = null;
        Iterator<OAuth2ProviderMetaData> iterator = oAuth2ProviderMetaDataList.iterator();
        while (infoProvider == null && iterator.hasNext()) {
            OAuth2ProviderMetaData metaData = iterator.next();
            if (provider.equals(metaData.getName())) {
                infoProvider = metaData.getInfoProvider();
            }
        }
        OAuth2User result = null;
        if (infoProvider != null) {
            Token authToken = new Token(token, "", "Octopus");

            result = infoProvider.retrieveUserInfo(authToken, req);
            result.setLocalId(externalInternalIdMapper.getLocalId(result.getId()));
        }
        return result;
    }
}
