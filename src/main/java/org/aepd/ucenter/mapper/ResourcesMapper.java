package org.aepd.ucenter.mapper;

import java.util.List;
import java.util.Map;

import org.aepd.ucenter.model.Resources;
import org.aepd.ucenter.util.MyMapper;

public interface ResourcesMapper extends MyMapper<Resources> {

    public List<Resources> queryAll();

    public List<Resources> loadUserResources(Map<String,Object> map);

    public List<Resources> queryResourcesListWithSelected(Integer rid);
}