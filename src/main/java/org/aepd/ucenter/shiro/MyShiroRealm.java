package org.aepd.ucenter.shiro;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.annotation.PostConstruct;
import javax.annotation.Resource;

import org.aepd.ucenter.config.ShiroConfig;
import org.aepd.ucenter.model.Resources;
import org.aepd.ucenter.model.User;
import org.aepd.ucenter.service.ResourcesService;
import org.aepd.ucenter.service.UserService;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.LockedAccountException;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authc.UnknownAccountException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.cache.Cache;
import org.apache.shiro.cas.CasRealm;
import org.apache.shiro.mgt.RealmSecurityManager;
import org.apache.shiro.session.Session;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.subject.SimplePrincipalCollection;
import org.apache.shiro.subject.support.DefaultSubjectContext;
import org.apache.shiro.util.ByteSource;
import org.crazycake.shiro.RedisCacheManager;
import org.crazycake.shiro.RedisSessionDAO;
import org.crazycake.shiro.SerializeUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.stereotype.Component;

/**
 * zxb 这个域实现充当CAS服务器的CAS客户端，用于认证和基本授权。 这个领域通过检查提交CasToken（基本上包装CAS服务票据）
 * 并且使用配置的CAS对照CAS服务器来验证它 TicketValidator。
 */
public class MyShiroRealm extends CasRealm {

	private static final Logger logger = LoggerFactory.getLogger(MyShiroRealm.class);

	@Resource
	private UserService userService;

	@Resource
	private ResourcesService resourcesService;

	@Autowired
	private RedisSessionDAO redisSessionDAO;


	// @Resource
	// private RedisCacheManager cacheManager;

	/**
	 * 权限认证，为当前登录的Subject授予角色和权限
	 * 
	 * @see 经测试：本例中该方法的调用时机为需授权资源被访问时
	 * @see 经测试：并且每次访问需授权资源时都会执行该方法中的逻辑，这表明本例中默认并未启用AuthorizationCache
	 * @see 经测试：如果连续访问同一个URL（比如刷新），该方法不会被重复调用，Shiro有一个时间间隔（也就是cache时间，在ehcache-
	 *      shiro.xml中配置），超过这个时间间隔再刷新页面，该方法会被执行
	 */
	@Override
	protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principalCollection) {

		logger.info("##################执行Shiro权限认证##################");
		// User{id=1, username='admin',
		// password='3ef7164d1f6167cb9f2658c07d3c2f0a', enable=1}
		// User user = (User) SecurityUtils.getSubject().getPrincipal();
		String loginName = (String) SecurityUtils.getSubject().getPrincipal();

		// String loginName =
		// (String)super.getAvailablePrincipal(principalCollection);
		User user = userService.selectByUsername(loginName);
		Map<String, Object> map = new HashMap<String, Object>();
		map.put("userid", user.getId());
		List<Resources> resourcesList = resourcesService.loadUserResources(map);
		// 权限信息对象info,用来存放查出的用户的所有的角色（role）及权限（permission）
		SimpleAuthorizationInfo info = new SimpleAuthorizationInfo();
		for (Resources resources : resourcesList) {
			info.addStringPermission(resources.getResurl());
		}
		return info;
	}

	/**
	 * 单Cas服务登录校验通过后，便会调用这个方法，并携带用户信息的Token参数
	 * 假设只要是有Token过来，就说明是有效的登录用户，不再对密码等做校验 方法名称 : doGetAuthenticationInfo 功能描述 :
	 * 验证当前登陆的Subject
	 * 
	 * @param authcToken
	 *            当前登录用户的token
	 * @return 验证信息
	 */
	@SuppressWarnings("deprecation")
	protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
		// 获取用户的输入的账号.
		AuthenticationInfo atoken = super.doGetAuthenticationInfo(token);
		String account = (String) atoken.getPrincipals().getPrimaryPrincipal();
			logger.info("当前Subject时获取到用户名为" + account);
			// 根据用户名，查找用户信息
			User user = userService.selectByUsername(account);
			if (user == null)
				throw new UnknownAccountException();
			System.out.println("<= user object =>" + user);
			System.out.println("<= user object =>" + user.getId());
			if (0 == user.getEnable()) {
				throw new LockedAccountException(); // 帐号锁定
			}
			// SimpleAuthenticationInfo authenticationInfo = new
			// SimpleAuthenticationInfo(
			// user, //用户
			// user.getPassword(), //密码
			// ByteSource.Util.bytes(username),
			// getName() //realm name
			// );

			Session session = SecurityUtils.getSubject().getSession();

			session.setAttribute("userSession", user);
			session.setAttribute("userSessionId", user.getId());
			
		// Session session = SecurityUtils.getSubject().getSession(false);
		// AuthenticationInfo authinfo = new SimpleAuthenticationInfo(user,
		// user.getPassword(),
		// ByteSource.Util.bytes(userName), getName());
		// Cache<Object, Object> cache =
		// cacheManager.getCache("shiro_redis_cache:");
		// cache.put("shiro_redis_cache:" + userName, session.getId());

		return atoken;
	}

	/**
	 * 根据userId 清除当前session存在的用户的权限缓存
	 * 
	 * @param userIds
	 *            已经修改了权限的userId
	 * 
	 *            //更新当前登录的用户的权限缓存 RoleResourcesServiceImpl->addRoleResources
	 *            方法调用 UserRoleServiceImpl->addUserRole 方法调用
	 */
	public void clearUserAuthByUserId(List<Integer> userIds) {
		if (null == userIds || userIds.size() == 0)
			return;
		// 获取所有session
		Collection<Session> sessions = redisSessionDAO.getActiveSessions();
		// 定义返回
		List<SimplePrincipalCollection> list = new ArrayList<SimplePrincipalCollection>();
		for (Session session : sessions) {
			// 获取session登录信息。
			Object obj = session.getAttribute(DefaultSubjectContext.PRINCIPALS_SESSION_KEY);
			if (null != obj && obj instanceof SimplePrincipalCollection) {
				// 强转
				SimplePrincipalCollection spc = (SimplePrincipalCollection) obj;
				// 判断用户，匹配用户ID。
				obj = spc.getPrimaryPrincipal();
				if (null != obj && obj instanceof User) {
					User user = (User) obj;
					System.out.println("user:" + user);
					// 比较用户ID，符合即加入集合
					if (null != user && userIds.contains(user.getId())) {
						list.add(spc);
					}
				}
			}
		}
		RealmSecurityManager securityManager = (RealmSecurityManager) SecurityUtils.getSecurityManager();
		MyShiroRealm realm = (MyShiroRealm) securityManager.getRealms().iterator().next();
		for (SimplePrincipalCollection simplePrincipalCollection : list) {
			realm.clearCachedAuthorizationInfo(simplePrincipalCollection);
		}
	}
}
