package be.c4j.ee.scurity.credentials.authentication.oauth2.google.json;

import be.c4j.ee.scurity.credentials.authentication.oauth2.google.GoogleUser;
import org.json.JSONException;
import org.json.JSONObject;
import org.json.JSONTokener;
import org.slf4j.Logger;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;

/**
 *
 */
@ApplicationScoped
public class GoogleJSONProcessor {

    @Inject
    private Logger logger;

    public GoogleUser extractGoogleUser(String json) {
        GoogleUser googleUser = null;
        try {
            JSONObject jsonObject = new JSONObject(new JSONTokener(json));

            if (!jsonObject.has("error")) {
                // TODO log error in case there is one
                googleUser = new GoogleUser();
                googleUser.setId(jsonObject.getString("id"));
                googleUser.setEmail(jsonObject.getString("email"));
                googleUser.setVerifiedEmail(jsonObject.getBoolean("verified_email"));
                googleUser.setLastName(jsonObject.getString("family_name"));
                googleUser.setFirstName(jsonObject.getString("given_name"));
                googleUser.setFullName(jsonObject.getString("name"));
                if (jsonObject.has("hd")) {
                    googleUser.setHd(jsonObject.getString("hd"));
                }
                googleUser.setLink(jsonObject.getString("link"));
                googleUser.setPicture(jsonObject.getString("picture"));
                googleUser.setGender(jsonObject.getString("gender"));
                googleUser.setLocale(jsonObject.getString("locale"));
            }

        } catch (JSONException e) {
            logger.warn(e.getMessage(), e);
        }
        return googleUser;
    }

}
