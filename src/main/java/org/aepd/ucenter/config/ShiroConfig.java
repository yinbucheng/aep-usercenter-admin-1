package org.aepd.ucenter.config;

import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import javax.servlet.Filter;

import org.aepd.ucenter.model.Resources;
import org.aepd.ucenter.service.ResourcesService;
import org.aepd.ucenter.shiro.MyShiroRealm;
import org.aepd.ucenter.util.LoginFormAuthenticationFilter;
import org.apache.shiro.authc.credential.HashedCredentialsMatcher;
import org.apache.shiro.cas.CasFilter;
import org.apache.shiro.cas.CasSubjectFactory;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.spring.LifecycleBeanPostProcessor;
import org.apache.shiro.spring.security.interceptor.AuthorizationAttributeSourceAdvisor;
import org.apache.shiro.spring.web.ShiroFilterFactoryBean;
import org.apache.shiro.web.filter.authc.LogoutFilter;
import org.apache.shiro.web.mgt.DefaultWebSecurityManager;
import org.apache.shiro.web.servlet.SimpleCookie;
import org.apache.shiro.web.session.mgt.DefaultWebSessionManager;
import org.crazycake.shiro.RedisCacheManager;
import org.crazycake.shiro.RedisManager;
import org.crazycake.shiro.RedisSessionDAO;
import org.jasig.cas.client.session.SingleSignOutFilter;
import org.jasig.cas.client.session.SingleSignOutHttpSessionListener;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.aop.framework.autoproxy.DefaultAdvisorAutoProxyCreator;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.boot.web.servlet.ServletListenerRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.filter.DelegatingFilterProxy;

import com.github.pagehelper.util.StringUtil;

import at.pollux.thymeleaf.shiro.dialect.ShiroDialect;
/**
 * Created by yangqj on 2017/4/23.
 */
@Configuration
public class ShiroConfig {
	
	private static final Logger logger = LoggerFactory.getLogger(ShiroConfig.class);

    // CasServerUrlPrefix
    public static final String casServerUrlPrefix = "http://localhost:8080/casServer";
    // Cas登录页面地址
    public static final String casLoginUrl = casServerUrlPrefix + "/login";

    // Cas登出页面地址
    public static final String casLogoutUrl = casServerUrlPrefix + "/logout";
    // 当前工程对外提供的服务地址
    public static final String shiroServerUrlPrefix = "http://localhost:9090";
    // casFilter UrlPattern
    // /shiro-cas: cas的过滤器的拦截规则
    public static final String casFilterUrlPattern = "/cas";
    // 登录地址
    public static final String loginUrl = casLoginUrl + "?service=" + shiroServerUrlPrefix + casFilterUrlPattern;
    // 登出地址（casserver启用service跳转功能，需在webapps\cas\WEB-INF\cas.properties文件中启用cas.logout.followServiceRedirects=true）
    public static final String logoutUrl = casLogoutUrl+"?service="+shiroServerUrlPrefix + casFilterUrlPattern;
    
    // 登录成功地址
    public static final String loginSuccessUrl = "/usersPage";
    // 权限认证失败跳转地址
    public static final String unauthorizedUrl = "/403.html";
	
	
    @Autowired(required = false)
    private ResourcesService resourcesService;

    @Value("${spring.redis.host}")
    private String host;

    @Value("${spring.redis.port}")
    private int port;

    @Value("${spring.redis.timeout}")
    private int timeout;

    @Value("${spring.redis.password}")
    private String password;

    //注入生命周期方法
    @Bean
    public static LifecycleBeanPostProcessor getLifecycleBeanPostProcessor() {
        return new LifecycleBeanPostProcessor();
    }

    /**
     * ShiroDialect，为了在thymeleaf里使用shiro的标签的bean
     * @return
     */
    @Bean
    public ShiroDialect shiroDialect() {
        return new ShiroDialect();
    }
    
    /**
     * cacheManager 缓存 redis实现
     * 使用的是shiro-redis开源插件
     * @return
     */
    public RedisCacheManager cacheManager() {
        RedisCacheManager redisCacheManager = new RedisCacheManager();
        redisCacheManager.setRedisManager(redisManager());
        return redisCacheManager;
    }
    
    /**
     * CAS过滤器
     *
 		此筛选器验证CAS服务票证以验证用户。它必须在CAS服务器识别的URL上进行配置。例如，在shiro.ini：
		 [主要]
		 casFilter = org.apache.shiro.cas.CasFilter
		 ...
		
		 [网址]
		 / shiro-cas = casFilter
		 ...
		 
		（例如：http：// host：port / mycontextpath / shiro-cas）
     */
    @Bean(name = "casFilter")
    public CasFilter getCasFilter() {
        CasFilter casFilter = new CasFilter();
        casFilter.setName("casFilter");
        casFilter.setEnabled(true);
        // 登录失败后跳转的URL，也就是 Shiro 执行 CasRealm 的 doGetAuthenticationInfo 方法向CasServer验证tiket
        //校验失败地址，这里失败继续重定向单点登录界面
        String failUrl = casServerUrlPrefix + "/login?service=" + shiroServerUrlPrefix + casFilterUrlPattern;
        //校验成功地址，登录成功后重定向的地址
        String successUrl = shiroServerUrlPrefix + "/usersPage";
        casFilter.setFailureUrl(failUrl);
        casFilter.setSuccessUrl(successUrl);
        return casFilter;
    }
    
    
    
    /**
     * 初始化此领域并可能启用缓存，具体取决于配置。
		当这个方法被调用时，执行下面的逻辑：
		如果cache属性已经设置，它将被用来缓存AuthorizingRealm.getAuthorizationInfo(org.apache.shiro.subject.PrincipalCollection) 
		方法调用返回的AuthorizationInfo对象。所有将来的调用getAuthorizationInfo将首先尝试使用此缓存，
		以缓解对底层数据存储的潜在不必要的调用。
		如果cache属性已不被设置，cacheManager属性将被检查。如果cacheManager已经设置了a ，
		它将被用来创建一个授权 cache，并且这个新创建的缓存将按照＃1的规定使用。
		如果没有设置(org.apache.shiro.cache.Cache) cache 或cacheManager 属性，缓存将被禁用，
		授权查找将委派给每个授权检查的子类实现。
     * @return
     */
    @Bean(name="myShiroCasRealm")
    public MyShiroRealm myShiroRealm(){
        MyShiroRealm myShiroRealm = new MyShiroRealm();
        //这是CAS服务器的URL（例如：http：// host：port / cas）
        myShiroRealm.setCasServerUrlPrefix(casServerUrlPrefix);
        //设置应用程序的CAS服务URL（例如：http：// host：port / mycontextpath / shiro-cas）
        myShiroRealm.setCasService(shiroServerUrlPrefix + casFilterUrlPattern);
        //myShiroRealm.setCacheManager(cacheManager);
        return myShiroRealm;
    }
    
    @Bean
    public LoginFormAuthenticationFilter getLoginFormAuthenticationFilter(){
    	return new LoginFormAuthenticationFilter();
    }
    
    @Bean(name="securityManager")
    public DefaultWebSecurityManager getDefaultWebSecurityManager(MyShiroRealm myShiroCasRealm){
        DefaultWebSecurityManager securityManager =  new DefaultWebSecurityManager();
        //设置realm.MyShiroRealm
        securityManager.setRealm(myShiroCasRealm);
        

        securityManager.setCacheManager(cacheManager());
        // 自定义session管理 使用redis
        securityManager.setSessionManager(sessionManager());
        // 指定 SubjectFactory
//        securityManager.setSubjectFactory(new CasSubjectFactory());
        return securityManager;
    }
    
   
    
    /**
     * ShiroFilterFactoryBean 处理拦截资源文件问题。
     * 注意：单独一个ShiroFilterFactoryBean配置是或报错的，因为在
     * 初始化ShiroFilterFactoryBean的时候需要注入：SecurityManager
     *
     Filter Chain定义说明
     1、一个URL可以配置多个Filter，使用逗号分隔
     2、当设置多个过滤器时，全部验证通过，才视为通过
     3、部分过滤器可指定参数，如perms，roles
     *
     */
    @Bean(name="shiroFilter")
    public ShiroFilterFactoryBean shiroFilter(SecurityManager securityManager,CasFilter casFilter){
    	System.out.println("ShiroConfiguration.shirFilter()");
        ShiroFilterFactoryBean shiroFilterFactoryBean  = new ShiroFilterFactoryBean();

        // 必须设置 SecurityManager
        shiroFilterFactoryBean.setSecurityManager(securityManager);
        // 如果不设置默认会自动寻找Web工程根目录下的"/login.jsp"页面
        shiroFilterFactoryBean.setLoginUrl(casServerUrlPrefix + "/login?service=" + shiroServerUrlPrefix + casFilterUrlPattern);
        // 登录成功后要跳转的链接
         shiroFilterFactoryBean.setSuccessUrl("/usersPage");
        //未授权界面;
        shiroFilterFactoryBean.setUnauthorizedUrl("/403");
        
        
        Map<String, Filter> filters = new HashMap<>();
        filters.put("casFilter", casFilter);
        
        LogoutFilter logoutFilter = new LogoutFilter();
        logoutFilter.setRedirectUrl(logoutUrl);
        filters.put("logout",logoutFilter);
        
        filters.put("authc",getLoginFormAuthenticationFilter());
        
        shiroFilterFactoryBean.setFilters(filters);
        
        //拦截器.
        Map<String,String> filterChainDefinitionMap = new LinkedHashMap<String,String>();
        
        filterChainDefinitionMap.put(casFilterUrlPattern, "casFilter");
        //filterChainDefinitionMap.put("/login","anon");
        
        filterChainDefinitionMap.put("/usersPage", "anon");
        //配置退出 过滤器,其中的具体的退出代码Shiro已经替我们实现了
        filterChainDefinitionMap.put("/logout", "logout");
        filterChainDefinitionMap.put("/css/**","anon");
        filterChainDefinitionMap.put("/js/**","anon");
        filterChainDefinitionMap.put("/img/**","anon");
        filterChainDefinitionMap.put("/font-awesome/**","anon");
        filterChainDefinitionMap.put("/templates/**","anon");
        
        //<!-- 过滤链定义，从上向下顺序执行，一般将 /**放在最为下边 -->:这是一个坑呢，一不小心代码就不好使了;
        //<!-- authc:所有url都必须认证通过才可以访问; anon:所有url都都可以匿名访问-->
        //自定义加载权限资源关系
        List<Resources> resourcesList = resourcesService.queryAll();
         for(Resources resources:resourcesList){

            if (StringUtil.isNotEmpty(resources.getResurl())) {
                String permission = "perms[" + resources.getResurl()+ "]";
                filterChainDefinitionMap.put(resources.getResurl(),permission);
            }
        }
        filterChainDefinitionMap.put("/**", "authc");
        shiroFilterFactoryBean.setFilterChainDefinitionMap(filterChainDefinitionMap);
        return shiroFilterFactoryBean;
    }
    
  
  
    
    /**
     * 注册单点登出listener
     * @return
     */
    @Bean
    public ServletListenerRegistrationBean singleSignOutHttpSessionListener(){
        ServletListenerRegistrationBean bean = new ServletListenerRegistrationBean();
        bean.setListener(new SingleSignOutHttpSessionListener());
//        bean.setName(""); //默认为bean name
        bean.setEnabled(true);
        //bean.setOrder(Ordered.HIGHEST_PRECEDENCE); //设置优先级
        return bean;
    }
    
    /**
     * 注册单点登出filter
     * @return
     */
    @Bean
    public FilterRegistrationBean singleSignOutFilter(){
        FilterRegistrationBean bean = new FilterRegistrationBean();
        bean.setName("singleSignOutFilter");
        bean.setFilter(new SingleSignOutFilter());
        bean.addUrlPatterns("/*");
        bean.setEnabled(true);
        //bean.setOrder(Ordered.HIGHEST_PRECEDENCE);
        return bean;
    }
    
    @Bean
    public DefaultAdvisorAutoProxyCreator getDefaultAdvisorAutoProxyCreator() {
        DefaultAdvisorAutoProxyCreator daap = new DefaultAdvisorAutoProxyCreator();
        daap.setProxyTargetClass(true);
        return daap;
    }
   
    
    /**
     * 注册DelegatingFilterProxy（Shiro）
     *
     * @return
     * @author SHANHY
     * @create  2016年1月13日
     */
    @Bean
    public FilterRegistrationBean delegatingFilterProxy() {
        FilterRegistrationBean filterRegistration = new FilterRegistrationBean();
        filterRegistration.setFilter(new DelegatingFilterProxy("shiroFilter"));
        //该值缺省为false,表示生命周期由SpringApplicationContext管理,设置为true则表示由ServletContainer管理
        filterRegistration.addInitParameter("targetFilterLifecycle", "true");
        filterRegistration.setEnabled(true);
        filterRegistration.addUrlPatterns("/*");
        return filterRegistration;
    }

    /**
     * 凭证匹配器
     * （由于我们的密码校验交给Shiro的SimpleAuthenticationInfo进行处理了
     *  所以我们需要修改下doGetAuthenticationInfo中的代码;
     * ）
     * @return
     */
    @Bean
    public HashedCredentialsMatcher hashedCredentialsMatcher(){
        HashedCredentialsMatcher hashedCredentialsMatcher = new HashedCredentialsMatcher();
        hashedCredentialsMatcher.setHashAlgorithmName("md5");//散列算法:这里使用MD5算法;
        hashedCredentialsMatcher.setHashIterations(1);//散列的次数，比如散列两次，相当于 md5(md5(""));
        return hashedCredentialsMatcher;
    }


    /**
     *  开启shiro aop注解支持.
     *  使用代理方式;所以需要开启代码支持;
     * @param securityManager
     * @return
     */
    @Bean
    public AuthorizationAttributeSourceAdvisor authorizationAttributeSourceAdvisor(SecurityManager securityManager){
        AuthorizationAttributeSourceAdvisor authorizationAttributeSourceAdvisor = new AuthorizationAttributeSourceAdvisor();
        authorizationAttributeSourceAdvisor.setSecurityManager(securityManager);
        return authorizationAttributeSourceAdvisor;
    }

    /**
     * 配置shiro redisManager
     * 使用的是shiro-redis开源插件
     * @return
     */
    @Bean(name="redisManager")
    public RedisManager redisManager() {
        RedisManager redisManager = new RedisManager();
        redisManager.setHost(host);
        redisManager.setPort(port);
        redisManager.setExpire(1800);// 配置缓存过期时间
        redisManager.setTimeout(timeout);
       // redisManager.setPassword(password);
        return redisManager;
    }

   


    /**
     * RedisSessionDAO shiro sessionDao层的实现 通过redis
     * 使用的是shiro-redis开源插件
     */
    @Bean
    public RedisSessionDAO redisSessionDAO() {
        RedisSessionDAO redisSessionDAO = new RedisSessionDAO();
        redisSessionDAO.setRedisManager(redisManager());
        return redisSessionDAO;
    }
    

    /**
     * shiro session的管理
     */
    @Bean
    public DefaultWebSessionManager sessionManager() {
        DefaultWebSessionManager sessionManager = new DefaultWebSessionManager();
        //会话超时时间，单位：毫秒
        sessionManager.setGlobalSessionTimeout(3600000);
        sessionManager.setSessionDAO(redisSessionDAO());
        
        //当跳出SHIRO SERVLET时如ERROR-PAGE容器会为JSESSIONID重新分配值导致登录会话丢失
        sessionManager.setSessionIdCookie(new SimpleCookie("SHRIOSESSIONID"));
        //sessionManager.setSessionValidationSchedulerEnabled(true);
        
        //定时清理失效会话, 清理用户直接关闭浏览器造成的孤立会话
        sessionManager.setSessionValidationInterval(3600000);
        return sessionManager;
    }
    
}
