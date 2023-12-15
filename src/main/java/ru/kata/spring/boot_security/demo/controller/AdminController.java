package ru.kata.spring.boot_security.demo.controller;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import ru.kata.spring.boot_security.demo.models.User;
import ru.kata.spring.boot_security.demo.service.RoleService;
import ru.kata.spring.boot_security.demo.service.UserService;

import java.security.Principal;
import java.util.List;

@Controller
public class AdminController {
    private final UserService userService;
    private final RoleService roleService;

    public AdminController(UserService userService, RoleService roleService) {
        this.userService = userService;
        this.roleService = roleService;
    }

    @GetMapping("/admin")
    public String showAllUsers(Model model, Principal principal) {
        List<User> allUsers = userService.getAllUsers();
        User authorizedUser = userService.findByUsername(principal.getName());
        model.addAttribute("newUser", new User()); // новый пользователь
        model.addAttribute("userPrincipal", authorizedUser); // авторизированный пользователь
        model.addAttribute("allUsers", allUsers); // все пользователи
        model.addAttribute("allRoles", authorizedUser != null ? authorizedUser.getRoles() : null); // все роли авторизованного пользователя
        model.addAttribute("allRolesBD", roleService.listRoles()); // все роли в БД
        return "admin_all_users";
    }

    @PostMapping("/saveUser")
    public String saveUser(@ModelAttribute("newUser") User user) {
        userService.saveUser(user);
        return "redirect:/admin";
    }

    @DeleteMapping("/{id}")
    public String deleteUser(@PathVariable("id") int id) {
        userService.deleteUser(id);
        return "redirect:/admin";
    }

    @PostMapping("/{id}")
    public String updateUser(@ModelAttribute("user") User user, @PathVariable("id") int id) {
        userService.updateUser(user, id);
        return "redirect:/admin";
    }

    @GetMapping("/{id}")
    public String getUser(Model model, @PathVariable("id") int id) {
        model.addAttribute("userGet", userService.getUser(id));
        model.addAttribute("roleList", roleService.listRoles());
        return "redirect:/admin";
    }
}