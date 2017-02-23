/*
 * Copyright 2014-2017 Rudy De Busscher (www.c4j.be)
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
package be.c4j.ee.security.sso.rest;

import be.c4j.ee.security.sso.rest.reflect.Bean;
import be.c4j.ee.security.sso.rest.reflect.Property;
import net.minidev.json.JSONObject;
import net.minidev.json.JSONStyle;
import net.minidev.json.parser.JSONParser;
import net.minidev.json.parser.ParseException;

import javax.enterprise.inject.Vetoed;
import java.io.Serializable;

import static net.minidev.json.JSONStyle.FLAG_IGNORE_NULL;

/**
 *
 */
@Vetoed
public class DefaultPrincipalUserInfoJSONProvider implements PrincipalUserInfoJSONProvider {


    @Override
    public String writeValue(Object data) {
        JSONObject result = new JSONObject();

        Bean<?> bean = Bean.forClass(data.getClass());
        Property[] declaredProperties = bean.getDeclaredProperties();
        String name;
        Object value;
        for (Property declaredProperty : declaredProperties) {
            name = declaredProperty.getName();
            value = bean.getProperty(name).get(data);
            if (value instanceof Serializable) {
                if (Property.isBasicPropertyType((Serializable) value)) {
                    result.put(name, value);
                } else {
                    result.put(name, writeValue(value));  // Recursive call
                }
            }
        }
        return result.toJSONString(new JSONStyle(FLAG_IGNORE_NULL));
    }

    @Override
    public <T> T readValue(String json, Class<T> classType) {
        Bean<T> bean = Bean.forClass(classType);
        T result = null;
        try {
            result = classType.newInstance();

            JSONParser parser = new JSONParser(JSONParser.MODE_PERMISSIVE);

            JSONObject jsonObject = (JSONObject) parser.parse(json);

            Object value;
            for (String propertyName : jsonObject.keySet()) {
                value = jsonObject.get(propertyName);

                Property property = bean.getProperty(propertyName);
                Class<?> actualType = property.getActualType();
                if (property.isWritable()) {
                    if (Property.isBasicPropertyType(actualType)) {
                        if (actualType.equals(Long.class) && value instanceof Integer) {
                            Integer intValue = (Integer) value;
                            property.set(result, intValue.longValue());
                        } else {
                            property.set(result, value);
                        }
                    } else {
                        property.set(result, readValue(value.toString(), actualType));
                    }
                }
            }
        } catch (InstantiationException e) {
            // FIXME
            e.printStackTrace();
        } catch (IllegalAccessException e) {
            // FIXME
            e.printStackTrace();
        } catch (ParseException e) {
            // FIXME
            e.printStackTrace();
        }
        return result;
    }
}
