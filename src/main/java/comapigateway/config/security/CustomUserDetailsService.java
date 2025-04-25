package comapigateway.config.security;

import java.util.HashSet;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import comapigateway.entities.User; // Entidad que representa al usuario en la base de datos.
import comapigateway.services.UserService; // Servicio para manejar operaciones relacionadas con usuarios.

import comapigateway.utils.SecurityUtils; // Utilidad para convertir roles a objetos GrantedAuthority.

/**
 * Clase personalizada que implementa la interfaz UserDetailsService de Spring Security.
 * Se utiliza para personalizar cómo se cargan los detalles de un usuario desde la base de datos.
 */
@Service // Marca esta clase como un servicio manejado por Spring.
public class CustomUserDetailsService implements UserDetailsService {
	private static final Logger logger = LoggerFactory.getLogger(CustomUserDetailsService.class);
    // Servicio para buscar usuarios en la base de datos.
    @Autowired
    private UserService userService;

    /**
     * Carga los detalles de un usuario por su nombre de usuario.
     *
     * @param username El nombre de usuario a buscar.
     * @return Un objeto UserDetails que contiene los detalles del usuario.
     * @throws UsernameNotFoundException Si el usuario no se encuentra en la base de datos.
     */
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
    	
        logger.info("[CustomUserDetailsService] loadUserByUsername...");
        
        // Busca al usuario en la base de datos utilizando el servicio.
    	//Buscar un usuario en la DB por su username y devolver los detalles necesarios para que Spring los compare.
    	//Este objeto tiene todo lo que guarde de el en la DB.
        User user = userService.findByUsername(username).orElseThrow(() -> new UsernameNotFoundException(""));
        
        logger.info("[CustomUserDetailsService] loadUserByUsername Usuario..." + user.toString());
        
        
        // Crea un conjunto de autoridades (roles) asignadas al usuario.
        Set<GrantedAuthority> authorities = new HashSet<>();
        authorities.add(SecurityUtils.convertToAuthority(user.getRole().name()));

        // Crea un objeto UserPrincipal para representar al usuario en el contexto de seguridad.
        UserPrincipal userPrincipal = new UserPrincipal();
        userPrincipal.setId(user.getId()); // Asigna el ID del usuario.
        userPrincipal.setAuthorities(authorities); // Asigna las autoridades (roles).
        userPrincipal.setPassword(user.getPassword()); // Asigna la contraseña del usuario.
        userPrincipal.setUser(user); // Asigna la referencia a la entidad User.
        userPrincipal.setUsername(username); // Asigna el nombre de usuario.

        // Devuelve el objeto UserPrincipal como los detalles del usuario autenticado.
        return userPrincipal;
    }
}
