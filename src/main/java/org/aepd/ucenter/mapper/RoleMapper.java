package org.aepd.ucenter.mapper;

import java.util.List;

import org.aepd.ucenter.model.Role;
import org.aepd.ucenter.util.MyMapper;

public interface RoleMapper extends MyMapper<Role> {
    public List<Role> queryRoleListWithSelected(Integer id);
}