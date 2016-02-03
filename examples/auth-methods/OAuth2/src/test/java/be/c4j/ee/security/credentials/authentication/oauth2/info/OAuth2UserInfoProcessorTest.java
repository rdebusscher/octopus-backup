package be.c4j.ee.security.credentials.authentication.oauth2.info;

import be.c4j.ee.security.credentials.authentication.oauth2.OAuth2User;
import org.json.JSONException;
import org.json.JSONObject;
import org.junit.Before;
import org.junit.Test;

import java.io.Serializable;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;


/**
 *
 */
public class OAuth2UserInfoProcessorTest {

    private OAuth2UserInfoProcessor processor;

    @Before
    public void setup() {
        processor = new OAuth2UserInfoProcessor() {};
    }

    @Test
    public void testProcessJSON() throws JSONException {

        OAuth2User user = new OAuth2User();
        List<String> keys = Collections.singletonList("key2");
        JSONObject json = new JSONObject("{ \"key1\" : \"value1\", \"key2\" : \"value2\", \"key3\" : \"value3\" }");
        processor.processJSON(user, json, keys);

        Map<Serializable, Serializable> userInfo = user.getUserInfo();
        assertThat(userInfo).hasSize(6);  // There are 4 other keys which are added by default

        assertThat(userInfo).containsEntry("key1", "value1");
        assertThat(userInfo).containsEntry("key3", "value3");
    }
}