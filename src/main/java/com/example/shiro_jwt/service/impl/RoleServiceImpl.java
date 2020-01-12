package com.example.shiro_jwt.service.impl;

import com.example.shiro_jwt.entity.Role;
import com.example.shiro_jwt.mapper.RoleMapper;
import com.example.shiro_jwt.service.IRoleService;
import com.baomidou.mybatisplus.extension.service.impl.ServiceImpl;
import org.springframework.stereotype.Service;

/**
 * <p>
 *  服务实现类
 * </p>
 *
 * @author jiawei
 * @since 2020-01-11
 */
@Service
public class RoleServiceImpl extends ServiceImpl<RoleMapper, Role> implements IRoleService {

}
