package com.example.demo;

import de.codecentric.boot.admin.server.config.AdminServerProperties;
import de.codecentric.boot.admin.server.config.EnableAdminServer;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;

@Configuration
@EnableAdminServer
@SpringBootApplication
public class DemoApplication {

	public static void main(String[] args) {
		SpringApplication.run(DemoApplication.class, args);
	}

    @Configuration
    public static class SecuritySecureConfig extends WebSecurityConfigurerAdapter {
        private final String adminContextPath;

        public SecuritySecureConfig(AdminServerProperties adminServerProperties) {
            this.adminContextPath = adminServerProperties.getContextPath();
        }

        @Override
        protected void configure(HttpSecurity http) throws Exception {
            // @formatter:off
            SavedRequestAwareAuthenticationSuccessHandler successHandler = new SavedRequestAwareAuthenticationSuccessHandler();
            successHandler.setTargetUrlParameter("redirectTo");
            successHandler.setDefaultTargetUrl(adminContextPath + "/");

            http.authorizeRequests()
                    .antMatchers(adminContextPath + "/assets/**").permitAll()//授予对所有静态资产和登录页面的公共访问权。
                    .antMatchers(adminContextPath + "/login").permitAll()
                    .anyRequest().authenticated()//	Every other request must be authenticated.其他每个请求都必须经过身份验证。
                    .and()
                    .formLogin().loginPage(adminContextPath + "/login").successHandler(successHandler).and()//Configures login and logout.配置登录和注销。
                    .logout().logoutUrl(adminContextPath + "/logout").and()
                    .httpBasic().and()//Enables HTTP-Basic support. This is needed for the Spring Boot Admin Client to register.使http基本支持。这是Spring Boot管理客户端注册所需要的。
                    .csrf()
                    .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())//	Enables CSRF-Protection using Cookies使用cookie启用csrf保护
                    .ignoringAntMatchers(
                            adminContextPath + "/instances",//	Disables CRSF-Protection the endpoint the Spring Boot Admin Client uses to register.禁用Spring Boot管理客户端用于注册的端点crsf保护。
                            adminContextPath + "/actuator/**"//Disables CRSF-Protection for the actuator endpoints.禁用执行器端点的crsf保护。
                    );
        }
    }
}
