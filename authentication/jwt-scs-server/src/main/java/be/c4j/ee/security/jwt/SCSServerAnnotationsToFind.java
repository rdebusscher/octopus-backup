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
package be.c4j.ee.security.jwt;

import be.c4j.ee.security.jwt.filter.IgnoreOctopusSCSRestFilter;
import be.c4j.ee.security.util.AnnotationsToFind;

import javax.enterprise.context.ApplicationScoped;
import java.lang.annotation.Annotation;
import java.util.ArrayList;
import java.util.List;

/**
 * So that the {@link be.c4j.ee.security.jwt.filter.OctopusAnnotationContainerRequestFilter} can find the annotation.
 */
@ApplicationScoped
public class SCSServerAnnotationsToFind implements AnnotationsToFind {

    @Override
    public List<Class<? extends Annotation>> getList() {
        List<Class<? extends Annotation>> result = new ArrayList<Class<? extends Annotation>>();
        result.add(IgnoreOctopusSCSRestFilter.class);
        return result;
    }
}
