package comapigateway.config.security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import comapigateway.models.Role;

import static org.springframework.security.config.Customizer.withDefaults;
import comapigateway.security.jwt.JwtAuthorizationFilter;


/**
 * Clase de configuración para la seguridad de la aplicación.
 * Configura la autenticación, autorización, CORS, manejo de sesiones y filtros de seguridad.
 */
@EnableWebSecurity // Habilita la integración de Spring Security en la aplicación.
@Configuration // Marca esta clase como una configuración de Spring.
public class SecurityConfig {

	private static final Logger logger = LoggerFactory.getLogger(SecurityConfig.class);

    // Servicio personalizado para cargar los detalles del usuario.
	@Autowired
	private CustomUserDetailsService customUserDetailsService;

    // Codificador de contraseñas utilizado para verificar las credenciales.
	@Autowired
	private PasswordEncoder passwordEncoder;

	
    /**
     * Bean que proporciona el AuthenticationManager, necesario para manejar la autenticación.
     *
     * @param authenticationConfiguration Configuración de autenticación de Spring Security.
     * @return AuthenticationManager para manejar la autenticación.
     * @throws Exception Si ocurre un error al obtener el AuthenticationManager.
     */
	@Bean
	AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {

		return authenticationConfiguration.getAuthenticationManager();
	}

	
    /**
     * Bean que define el filtro de autorización basado en JWT.
     *
     * @return Instancia de JwtAuthorizationFilter.
     */
	@Bean
	JwtAuthorizationFilter jwtAuthorizationFilter() {
		return new JwtAuthorizationFilter();
	}
	
	
    /**
     * Configura la cadena de filtros de seguridad (SecurityFilterChain).
     *
     * @param http Objeto HttpSecurity para configurar la seguridad HTTP.
     * @return La configuración de la cadena de filtros.
     * @throws Exception Si ocurre un error durante la configuración.
     */
	@Bean
	SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
		logger.info("Configurando AuthenticationManagerBuilder");
		//"Dame el configurador de autenticación para decirte cómo manejar usuarios y passwords".
		AuthenticationManagerBuilder auth = http.getSharedObject(AuthenticationManagerBuilder.class);

		//Usa este UserDetailsService (customUserDetailsService) para buscar usuarios.
		     // ---> Aquí es donde Spring irá a buscar en la base de datos por un username.
		     // ---> Usa este PasswordEncoder (passwordEncoder) para comparar contraseñas. Generalmente usas BCryptPasswordEncoder.
		/*📌 Aquí defino la lógica de autenticación: cómo Spring debe obtener al usuario y validar la contraseña. */
		logger.info("Configurando AuthenticationManagerBuilder que use CustomUserDetailsService para buscar usuarios");
		
		auth.userDetailsService(customUserDetailsService).passwordEncoder(passwordEncoder);

		//  -->   "Ya terminé de decirte cómo autenticar, ahora créate y queda listo para usarse".
		AuthenticationManager authenticationManager = auth.build();

        http.cors(withDefaults());
        http.csrf(csrf -> csrf.disable());
		http.authenticationManager(authenticationManager);
        http.sessionManagement(management -> management.sessionCreationPolicy(SessionCreationPolicy.STATELESS));

        http.authorizeHttpRequests(requests -> requests
                .antMatchers("/authentication/sign-in", "/authentication/sign-up").permitAll()
                .antMatchers("/swagger-ui/index.html", "/swagger-ui/**").permitAll()
                .antMatchers(HttpMethod.POST, "/authentication/login").permitAll()
                .antMatchers(HttpMethod.GET, "/api/recordatorio/todos").permitAll()
                .antMatchers(HttpMethod.GET, "/api/recordatorio/usuario/*").permitAll()
                
                //Con parametros
                .antMatchers(HttpMethod.GET, "/api/data/inicial").permitAll()

                .antMatchers(HttpMethod.PATCH, "/api/recordatorio/actualizar").permitAll()
                .antMatchers(HttpMethod.DELETE, "/api/recordatorio/eliminar/*").permitAll()
                .antMatchers(HttpMethod.POST, "/api/recordatorio/crear").permitAll()
                .antMatchers(HttpMethod.POST, "/api/cooperacion/crear").permitAll()
                .antMatchers("/cursos/**")//El resto se requiere authenticacion
                .hasRole(Role.ADMIN.name()) //Y con role admin
                .anyRequest()
                .authenticated());

		http.addFilterBefore(jwtAuthorizationFilter(), UsernamePasswordAuthenticationFilter.class);

		return http.build();
	}

    /**
     * Configura CORS para permitir solicitudes desde cualquier origen.
     *
     * @return Configuración CORS.
     */
	@Bean
	WebMvcConfigurer corsConfigurer() {
		return new WebMvcConfigurer() {
			@Override
			public void addCorsMappings(CorsRegistry registry) {
				registry.addMapping("/**").allowedOrigins("*");
			}
		};
	}
/*↓ Pides el builder de autenticación
AuthenticationManagerBuilder auth = http.getSharedObject(...)

↓ Le dices cómo autenticar (con qué servicio y qué encoder)
auth.userDetailsService(...).passwordEncoder(...)

↓ Le dices: listo, construye el manager de autenticación
AuthenticationManager authenticationManager = auth.build();

↓ Finalmente lo registras en la configuración de seguridad
http.authenticationManager(authenticationManager);
*/
}
