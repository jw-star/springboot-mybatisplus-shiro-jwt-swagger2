package com.example.shiro_jwt.config;

import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
import com.example.shiro_jwt.common.JwtUtil;
import com.example.shiro_jwt.entity.Permission;
import com.example.shiro_jwt.entity.Role;
import com.example.shiro_jwt.entity.RolePermission;
import com.example.shiro_jwt.entity.User;
import com.example.shiro_jwt.myentity.JwtToken;
import com.example.shiro_jwt.service.IPermissionService;
import com.example.shiro_jwt.service.IRolePermissionService;
import com.example.shiro_jwt.service.IRoleService;
import com.example.shiro_jwt.service.IUserService;
import org.apache.shiro.authc.*;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.util.ByteSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * @author Mr.Li
 * @create 2018-07-12 15:23
 * @desc
 **/
@Component
public class MyRealm extends AuthorizingRealm {

    @Autowired
    private IUserService userService;
    @Autowired
    private IRoleService roleService;
    @Autowired
    private IRolePermissionService iRolePermissionService;
    @Autowired
    private IPermissionService iPermissionService;
    /**
     * 必须重写此方法，不然Shiro会报错
     */
    @Override
    public boolean supports(AuthenticationToken token) {
        return token != null && token instanceof JwtToken;
    }

    /**
     * 只有当需要检测用户权限的时候才会调用此方法
     * 将权限和角色绑定返回
     */
    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
        String username = JwtUtil.getUsername(principals.toString());
        QueryWrapper<User> userQueryWrapper = new QueryWrapper<>();
        userQueryWrapper.eq("username",username);
        User user = userService.getOne(userQueryWrapper);
        SimpleAuthorizationInfo simpleAuthorizationInfo = new SimpleAuthorizationInfo();
        Role role = roleService.getById(user.getRoleId());
        Set<String> roleSet = new HashSet<>();// 放置角色，我这里只设计成单用户单角色，简单点
        Set<String> permissionSet = new HashSet<>();//放置权限
        roleSet.add(role.getRoleName());
        QueryWrapper<RolePermission> iRolePermissionServiceQueryWrapper = new QueryWrapper<>();
        iRolePermissionServiceQueryWrapper.eq("role_id",user.getRoleId());
        List<RolePermission> rolePermissionList = iRolePermissionService.list(iRolePermissionServiceQueryWrapper);
        for (RolePermission rolePermission : rolePermissionList) {
            Permission permission = iPermissionService.getById(rolePermission.getPermissionId());
            permissionSet.add(permission.getName());
        }
        simpleAuthorizationInfo.setRoles(roleSet);
        simpleAuthorizationInfo.setStringPermissions(permissionSet);
        return simpleAuthorizationInfo;
    }

    /**
     * 默认使用此方法进行用户名正确与否验证，错误抛出异常即可。
     */
    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken auth) throws AuthenticationException {
        String token = (String) auth.getCredentials();
        // 解密获得username，用于和数据库进行对比
        String username = JwtUtil.getUsername(token);

        if (username == null) {
            throw new AuthenticationException("token无效");
        }
        QueryWrapper<User> userQueryWrapper = new QueryWrapper<>();
        userQueryWrapper.eq("username",username);
        User userBean = this.userService.getOne(userQueryWrapper);
        if (userBean == null) {
            throw new UnknownAccountException("用户不存在!");
        }
        if (!JwtUtil.verify(token, username, userBean.getPassword())) {
            throw new IncorrectCredentialsException ("用户名或密码错误");
        }
        /*LockedAccountException  用户已锁定异常*/
        return new SimpleAuthenticationInfo(token,token,getName());
        /*return new SimpleAccount(
               token,
                ByteSource.Util.bytes(userBean.getUsername()),// 加盐，用户名做盐值
                getName()
        );*/
    }
}