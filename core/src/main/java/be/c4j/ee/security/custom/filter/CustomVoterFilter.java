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
 *
 */
package be.c4j.ee.security.custom.filter;

import be.c4j.ee.security.CustomAccessDecissionVoterContext;
import be.c4j.ee.security.custom.AbstractGenericVoter;
import be.c4j.ee.security.util.CDIUtil;
import org.apache.deltaspike.core.api.provider.BeanManagerProvider;
import org.apache.deltaspike.security.api.authorization.AccessDecisionVoterContext;
import org.apache.shiro.web.filter.authz.AuthorizationFilter;

import javax.enterprise.inject.spi.BeanManager;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;

/**
 *
 */
public class CustomVoterFilter extends AuthorizationFilter {


    @Override
    protected boolean isAccessAllowed(ServletRequest request, ServletResponse response, Object mappedValue) throws Exception {

        String[] voters = (String[]) mappedValue;

        BeanManager bm = BeanManagerProvider.getInstance().getBeanManager();

        String url = ((HttpServletRequest) request).getRequestURL().toString();
        AccessDecisionVoterContext context = new CustomAccessDecissionVoterContext(url, new Object[]{request});

        boolean permitted = true;

        for (String voter : voters) {
            AbstractGenericVoter voterObj = CDIUtil.getContextualReferenceByName(bm, voter, AbstractGenericVoter.class);
            if (!voterObj.verify(context)) {
                permitted = false;
                break;
            }
        }
        return permitted;
    }
}
