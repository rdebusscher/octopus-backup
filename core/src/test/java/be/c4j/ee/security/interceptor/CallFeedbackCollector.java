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

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 *
 */
public final class CallFeedbackCollector {

    private static Set<String> calledMethods = new HashSet<String>();

    private CallFeedbackCollector() {
    }

    public static void addCallFeedback(String calledMethod) {
        calledMethods.add(calledMethod);
    }

    public static void reset() {
        calledMethods.clear();
    }

    public static List<String> getCallFeedback() {
        return new ArrayList<String>(calledMethods);
    }
}
