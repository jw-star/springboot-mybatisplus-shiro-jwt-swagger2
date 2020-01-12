package com.example.shiro_jwt.service.impl;

import com.example.shiro_jwt.entity.Permission;
import com.example.shiro_jwt.mapper.PermissionMapper;
import com.example.shiro_jwt.service.IPermissionService;
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
public class PermissionServiceImpl extends ServiceImpl<PermissionMapper, Permission> implements IPermissionService {

}
