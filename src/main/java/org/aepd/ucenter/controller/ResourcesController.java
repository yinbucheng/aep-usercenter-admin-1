package org.aepd.ucenter.controller;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.annotation.Resource;

import org.aepd.ucenter.model.Resources;
import org.aepd.ucenter.model.User;
import org.aepd.ucenter.service.ResourcesService;
import org.aepd.ucenter.service.UserService;
import org.aepd.ucenter.shiro.ShiroService;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.subject.Subject;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.github.pagehelper.PageInfo;

/**
 * Created by yangqj on 2017/4/25.
 */
@RestController
@RequestMapping("/resources")
public class ResourcesController {

    @Resource
    private ResourcesService resourcesService;
    @Resource
    private ShiroService shiroService;

    @Resource
	private UserService userService;

    @RequestMapping
    public Map<String,Object> getAll(Resources resources, String draw,
                                     @RequestParam(required = false, defaultValue = "1") int start,
                                     @RequestParam(required = false, defaultValue = "10") int length){
        Map<String,Object> map = new HashMap<>();
        PageInfo<Resources> pageInfo = resourcesService.selectByPage(resources, start, length);
        System.out.println("pageInfo.getTotal():"+pageInfo.getTotal());
        map.put("draw",draw);
        map.put("recordsTotal",pageInfo.getTotal());
        map.put("recordsFiltered",pageInfo.getTotal());
        map.put("data", pageInfo.getList());
        return map;
    }

    @RequestMapping("/resourcesWithSelected")
    public List<Resources> resourcesWithSelected(Integer rid){
        return resourcesService.queryResourcesListWithSelected(rid);
    }

    @RequestMapping("/loadMenu")
    public List<Resources> loadMenu(){
        Map<String,Object> map = new HashMap<>();
        Integer userid = (Integer) SecurityUtils.getSubject().getSession().getAttribute("userSessionId");
        
        Subject currentUser = SecurityUtils.getSubject();
        String loginName = (String) currentUser.getPrincipal();
        User user = userService.selectByUsername(loginName);
        //User user =  (User)SecurityUtils.getSubject().getSession().getAttribute("userSession");
        System.out.println("user.id=>"+user.getId());
        
        map.put("type",1);
        map.put("userid",userid);
        
        List<Resources> resourcesList = resourcesService.loadUserResources(map);
        return resourcesList;
    }

    //@CacheEvict(cacheNames="resources", allEntries=true)
    @RequestMapping(value = "/add")
    public String add(Resources resources){
        try{
            resourcesService.save(resources);
            //更新权限
            shiroService.updatePermission();
            return "success";
        }catch (Exception e){
            e.printStackTrace();
            return "fail";
        }
    }
    //@CacheEvict(cacheNames="resources", allEntries=true)
    @RequestMapping(value = "/delete")
    public String delete(Integer id){
        try{
            resourcesService.delete(id);
            //更新权限
            shiroService.updatePermission();
            return "success";
        }catch (Exception e){
            e.printStackTrace();
            return "fail";
        }
    }
}
