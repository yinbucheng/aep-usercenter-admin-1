package org.aepd.ucenter.controller;

import org.aepd.ucenter.config.ShiroConfig;
import org.aepd.ucenter.model.User;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.LockedAccountException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.subject.Subject;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import javax.servlet.http.HttpServletRequest;

/**
 * zxb
 */
@Controller
public class HomeController {
	
	/**
	 * 转向CAS进行验证，验证通过后返回token,调用后就会进去我们自定义的realm中的
	 * doGetAuthenticationInfo()方法
	 * @return
	 */
    @RequestMapping(value="/login",method= RequestMethod.GET)
    public String login(){
    	System.out.println("ShiroConfig.loginUrl ==>"+ShiroConfig.loginUrl);
        return "redirect:" + ShiroConfig.loginUrl;
    }

//    @RequestMapping(value="/login",method=RequestMethod.POST)
//    public String login(HttpServletRequest request, User user){
//        if (StringUtils.isEmpty(user.getUsername()) || StringUtils.isEmpty(user.getPassword())) {
//            request.setAttribute("msg", "用户名或密码不能为空！");
//            return "login";
//        }
//        Subject subject = SecurityUtils.getSubject();
//        UsernamePasswordToken token=new UsernamePasswordToken(user.getUsername(),user.getPassword());
//        try {
//            subject.login(token);
//            return "redirect:usersPage";
//        }catch (LockedAccountException lae) {
//            token.clear();
//            request.setAttribute("msg", "用户已经被锁定不能登录，请与管理员联系！");
//            return "login";
//        } catch (AuthenticationException e) {
//            token.clear();
//            request.setAttribute("msg", "用户或密码不正确！");
//            return "login";
//        }
//    }
    
    //@RequestMapping(value={"/usersPage",""})
    @RequestMapping("/usersPage")
    public String usersPage(){
        return "user/users";
    }

    @RequestMapping("/rolesPage")
    public String rolesPage(){
        return "role/roles";
    }

    @RequestMapping("/resourcesPage")
    public String resourcesPage(){
        return "resources/resources";
    }

    @RequestMapping("/403")
    public String forbidden(){
        return "403";
    }
    
//    @RequestMapping(value="/logout",method=RequestMethod.GET)  
//    public String logout(RedirectAttributes redirectAttributes ){ 
//        //使用权限管理工具进行用户的退出，跳出登录，给出提示信息
//        SecurityUtils.getSubject().logout();  
//        redirectAttributes.addFlashAttribute("message", "您已安全退出");  
//        return "redirect:/login";
//    } 
//    
    @RequestMapping(value = "/logout", method = { RequestMethod.GET,
            RequestMethod.POST })
    public String loginout()
    {
        return "redirect:"+ShiroConfig.logoutUrl;
    }
}
