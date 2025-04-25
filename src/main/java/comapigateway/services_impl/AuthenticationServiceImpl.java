package comapigateway.services_impl;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import comapigateway.config.security.UserPrincipal;
import comapigateway.entities.User;
import comapigateway.models.UserDTO;
import comapigateway.repositories.UserRepository;
import comapigateway.security.jwt.JwtProvider;
import comapigateway.services.AuthenticationService;

@Service
public class AuthenticationServiceImpl implements AuthenticationService {

	private static final Logger logger = LoggerFactory.getLogger(AuthenticationServiceImpl.class);

	@Autowired
	private AuthenticationManager authenticationManager;

	@Autowired
	private JwtProvider jwtProvider;

	@Autowired
	private UserRepository userRepository;

	private final static String mesjError = "Credenciales inválidas";

	/*
	 * Cuando hago login, Spring llama automáticamente a mi loadUserByUsername(),
	 * que busca el usuario, y le devuelve un objeto UserDetails con el password
	 * hash. Luego Spring compara la contraseña enviada con la almacenada usando el
	 * PasswordEncoder, y si coincide, me autentica.
	 */
	@Override
	public UserDTO signInAndReturnJWT(User signInRequest) {

		logger.info("[AuthenticationServiceImpl] signInAndReturnJWT Validando usuario entrante...");
		// logger.info("Usuario: " + signInRequest.getUsername());
		// logger.info("Pass: " + signInRequest.getPassword());

		try {

			// logger.info("Usuario encontrado: " + user.toString());
			// 📌UsernamePasswordAuthenticationToken Es una hoja que llenas con tu nombre y
			// contraseña, para que seguridad (Spring) la revise.
			// 📌 Este objeto es solo un formulario con datos. Aún no está aprobado.solo son
			// los datos de la DB del usuario almacenado
			UsernamePasswordAuthenticationToken intentoAutenticacion = new UsernamePasswordAuthenticationToken(
					signInRequest.getUsername(), signInRequest.getPassword());

			// Busca tu registro en el sistema (con
			// CustomUserDetailsService.loadUserByUsername("pablo"))
			// Lee tu clave almacenada (la encriptada que está en la base)
			// Compara tu clave con la que acabas de decir (con PasswordEncoder.matches)
			// ¿Coinciden?

			Authentication resultado = authenticationManager.authenticate(intentoAutenticacion);

			logger.info("[AuthenticationServiceImpl] signInAndReturnJWT  Usuario autenticado: "
					+ resultado.getPrincipal().toString());

			UserPrincipal userPrincipal = (UserPrincipal) resultado.getPrincipal(); // Obtener los detalles del usuario
																					// autenticado

			String jwt = jwtProvider.generateToken(userPrincipal); // Genarar un token usando el usuario principal

			User usuarioAuthenticado = userPrincipal.getUser();
			usuarioAuthenticado.setToken(jwt);

			// logger.info("Autenticación exitosa. Generando JWT...");

			return new UserDTO(usuarioAuthenticado.getId(), usuarioAuthenticado.getUsername(),
					usuarioAuthenticado.getName(), usuarioAuthenticado.getApellido(), usuarioAuthenticado.getTelefono(),
					usuarioAuthenticado.getEmail(), usuarioAuthenticado.getFechaCreacion(),
					usuarioAuthenticado.getRole(), usuarioAuthenticado.getToken());

		} catch (BadCredentialsException ex) {
			logger.error(
					"[AuthenticationServiceImpl] BadCredentialsException Usuario no encontrado. " + ex.getMessage());
			// Contraseña incorrecta o usuario no encontrado
			throw ex;

		} catch (AuthenticationException ex) {
			logger.error("[AuthenticationServiceImpl] AuthenticationException " + ex.getMessage());
			throw ex; // Maneja errores de autenticación específicos

		} catch (Exception ex) {
			logger.error("[AuthenticationServiceImpl] Exception" + ex.getMessage());
			throw new RuntimeException("Error inesperado durante el inicio de sesión. Por favor, intente más tarde.");
		}
	}
	
	/*
	 * “El AuthenticationManager autentica usando el UserDetailsService, compara
	 * contraseñas con el PasswordEncoder, y me devuelve un Authentication listo. No
	 * necesito buscar usuarios dos veces, ni validar contraseñas a mano.”
	 * 
	 * "El AuthenticationManager se encarga de todo: buscar usuario, validar contraseña, y devolverme el usuario autenticado si todo está bien."
	 */
}
