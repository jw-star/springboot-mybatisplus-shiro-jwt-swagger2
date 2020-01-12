package com.example.shiro_jwt.controller;


import com.example.shiro_jwt.common.PasswordGen;
import com.example.shiro_jwt.common.api.CommonResult;
import com.example.shiro_jwt.common.api.ResultCode;
import com.example.shiro_jwt.entity.User;
import com.example.shiro_jwt.myentity.JwtToken;
import com.example.shiro_jwt.common.JwtUtil;
import com.example.shiro_jwt.service.IUserService;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authz.UnauthorizedException;
import org.apache.shiro.authz.annotation.Logical;
import org.apache.shiro.authz.annotation.RequiresRoles;
import org.apache.shiro.subject.Subject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * <p>
 *  前端控制器
 * </p>
 *
 * @author jiawei
 * @since 2020-01-08
 */
@RestController
@RequestMapping("/user")
@Api(value = "SpringBoot集成Shiro JWT测试接口", tags = "LoginController")
public class UserController {
    @Autowired
    private IUserService service;

    @ApiOperation(value = "用户登录")
    @RequestMapping(value = "/login",method = RequestMethod.POST)
    public CommonResult<JwtToken> login(@RequestParam("username") String username, @RequestParam("password") String password){
        //String s = PasswordGen.encryptPassword("SHA-256", password, username, 3);
        String token = JwtUtil.sign(username, password);
        JwtToken jwtToken=new JwtToken(token);
        Subject subject = SecurityUtils.getSubject();

            subject.login(jwtToken);

        return CommonResult.success(jwtToken,"登录成功");
    }
    @RequiresRoles(logical = Logical.OR, value = {"商品管员"})
    @ApiOperation(value = "用户列表查询")
    @RequestMapping(value = "/list",method = RequestMethod.GET)
    public CommonResult list(){
        List<User> list = service.list();
        System.out.println(list);
        return  CommonResult.success(list);
    }

    /**
     * 退出
     * @return
     */
    @ApiOperation(value = "退出登录")
    @RequestMapping(value="logout",method =RequestMethod.GET)
    public ResultCode logout(){
        Map<String, Object> resultMap = new LinkedHashMap<String, Object>();
        try {
            //退出
            SecurityUtils.getSubject().logout();
        } catch (Exception e) {
            System.err.println(e.getMessage());
        }
        return ResultCode.SUCCESS;
    }
    @ExceptionHandler(UnauthorizedException.class)
    public ResultCode authorzation(Exception ex) {
        return ResultCode.FORBIDDEN;// 无权限返回的信息
    }
}