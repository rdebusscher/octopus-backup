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
package be.c4j.ee.security.interceptor;

import java.lang.annotation.Annotation;
import java.util.HashSet;
import java.util.Set;

/**
 *
 */
public class AnnotationInfo {

    private Set<Annotation> methodAnnotations = new HashSet<Annotation>();
    private Set<Annotation> classAnnotations = new HashSet<Annotation>();


    public void addMethodAnnotation(Annotation annotation) {
        methodAnnotations.add(annotation);
    }

    public void addClassAnnotation(Annotation annotation) {
        classAnnotations.add(annotation);
    }

    public Set<Annotation> getMethodAnnotations() {
        methodAnnotations.remove(null);
        return methodAnnotations;
    }

    public Set<Annotation> getClassAnnotations() {
        classAnnotations.remove(null);
        return classAnnotations;
    }
}
