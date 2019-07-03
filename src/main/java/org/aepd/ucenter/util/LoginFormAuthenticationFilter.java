package org.aepd.ucenter.util;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.web.filter.authc.FormAuthenticationFilter;
import org.apache.shiro.web.util.WebUtils;

public class LoginFormAuthenticationFilter extends FormAuthenticationFilter {

	@Override
	protected boolean onLoginSuccess(AuthenticationToken token, Subject subject, ServletRequest request,
			ServletResponse response) throws Exception {
		
		//清理原先的地址
		WebUtils.getAndClearSavedRequest(request);
		WebUtils.redirectToSavedRequest(request, response, "/usersPage");
		
		return super.onLoginSuccess(token, subject, request, response);
	}
}
