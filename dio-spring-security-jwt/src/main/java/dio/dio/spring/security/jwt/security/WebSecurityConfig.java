package dio.dio.spring.security.jwt.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class WebSecurityConfig {
    
   @Bean
    public BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    private static final String[] SWAGGER_WHITELIST = {
            "/v2/api-docs",
            "/swagger-resources",
            "/swagger-resources/**",
            "/configuration/ui",
            "/configuration/security",
            "/swagger-ui.html",
            "/webjars/**"
    };

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.headers((headers) -> headers
            .frameOptions(Customizer.withDefaults()).disable())
            .csrf(AbstractHttpConfigurer::disable)
            .cors(AbstractHttpConfigurer::disable)
            .addFilterAfter(new JWTFilter(), UsernamePasswordAuthenticationFilter.class)
            .authorizeHttpRequests((authorize) -> authorize.requestMatchers(HttpMethod.DELETE).hasRole("ADMIN")
            .requestMatchers(SWAGGER_WHITELIST).permitAll()
            .requestMatchers("/").permitAll()
            .requestMatchers("/h2-console/**").permitAll()
            .requestMatchers(HttpMethod.POST,"/login").permitAll()
            .requestMatchers(HttpMethod.POST,"/users").permitAll()
            .requestMatchers(HttpMethod.GET,"/users").hasAnyRole("USERS","MANAGERS")
            .requestMatchers("/managers").hasAnyRole("MANAGERS")
            .anyRequest().authenticated())
            .sessionManagement(httpSecuritySessionManagementConfigurer -> 
                httpSecuritySessionManagementConfigurer.sessionCreationPolicy(SessionCreationPolicy.STATELESS));

        return http.build();
    }
    
    // @Bean //HABILITANDO ACESSAR O H2-DATABSE NA WEB
    // public ServletRegistrationBean h2servletRegistration(){
    //     ServletRegistrationBean registrationBean = new ServletRegistrationBean();
    //     registrationBean.addUrlMappings("/h2-console/*");
    //     return registrationBean;
    // }
}







// import org.springframework.boot.web.servlet.ServletRegistrationBean;
// import org.springframework.context.annotation.Bean;
// import org.springframework.context.annotation.Configuration;
// import org.springframework.http.HttpMethod;
// import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
// import org.springframework.security.config.annotation.web.builders.HttpSecurity;
// import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
// import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
// import org.springframework.security.config.http.SessionCreationPolicy;
// import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
// import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
// import org.h2.server.web.WebServlet;

// @Configuration
// @EnableWebSecurity
// @EnableGlobalMethodSecurity(prePostEnabled = true)
// public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
//     @Bean
//     public BCryptPasswordEncoder encoder(){
//         return new BCryptPasswordEncoder();
//     }

//     private static final String[] SWAGGER_WHITELIST = {
//             "/v2/api-docs",
//             "/swagger-resources",
//             "/swagger-resources/**",
//             "/configuration/ui",
//             "/configuration/security",
//             "/swagger-ui.html",
//             "/webjars/**"
//     };
//     @Override
//     protected void configure(HttpSecurity http) throws Exception {
//         http.headers().frameOptions().disable();
//         http.cors().and().csrf().disable()
//                 .addFilterAfter(new JWTFilter(), UsernamePasswordAuthenticationFilter.class)
//                 .authorizeRequests()
//                 .antMatchers(SWAGGER_WHITELIST).permitAll()
//                 .antMatchers("/h2-console/**").permitAll()
//                 .antMatchers(HttpMethod.POST,"/login").permitAll()
//                 .antMatchers(HttpMethod.POST,"/users").permitAll()
//                 .antMatchers(HttpMethod.GET,"/users").hasAnyRole("USERS","MANAGERS")
//                 .antMatchers("/managers").hasAnyRole("MANAGERS")
//                 .anyRequest().authenticated()
//                 .and()
//                 .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
//     }
//     @Bean //HABILITANDO ACESSAR O H2-DATABSE NA WEB
//     public ServletRegistrationBean h2servletRegistration(){
//         ServletRegistrationBean registrationBean = new ServletRegistrationBean( new WebServlet());
//         registrationBean.addUrlMappings("/h2-console/*");
//         return registrationBean;
//     }
// }
