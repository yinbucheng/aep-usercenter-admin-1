package org.aepd.ucenter.mapper;


import java.util.List;

import org.aepd.ucenter.model.UserRole;
import org.aepd.ucenter.util.MyMapper;

public interface UserRoleMapper extends MyMapper<UserRole> {
    public List<Integer> findUserIdByRoleId(Integer roleId);
}