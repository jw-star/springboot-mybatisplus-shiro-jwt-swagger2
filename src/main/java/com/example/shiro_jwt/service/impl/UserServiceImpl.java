package com.example.shiro_jwt.service.impl;

import com.example.shiro_jwt.entity.User;
import com.example.shiro_jwt.mapper.UserMapper;
import com.example.shiro_jwt.service.IUserService;
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
public class UserServiceImpl extends ServiceImpl<UserMapper, User> implements IUserService {

}
