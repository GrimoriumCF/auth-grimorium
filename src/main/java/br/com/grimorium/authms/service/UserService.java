package br.com.grimorium.authms.service;

import br.com.grimorium.authms.dto.PasswordChangeDTO;
import br.com.grimorium.authms.dto.UserCreateDTO;
import br.com.grimorium.authms.dto.UserResponseDTO;
import br.com.grimorium.authms.exception.NotFoundException;
import br.com.grimorium.authms.exception.UsernameExistException;
import br.com.grimorium.authms.jwt.JwtService;
import br.com.grimorium.authms.model.UserGrimorium;
import br.com.grimorium.authms.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.stream.Collectors;


@Service
public class UserService implements UserDetailsService {
    private final UserRepository usuarioRepository;

    @Autowired
    private final PasswordEncoder passwordEncoder;

    public UserService(UserRepository usuarioRepository, PasswordEncoder passwordEncoder) {
        this.usuarioRepository = usuarioRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @Transactional
    public UserResponseDTO save(UserCreateDTO ud) throws UsernameExistException {
        UserGrimorium byUsername = usuarioRepository.findByUsername(ud.username());
        if (byUsername != null) {
            throw new UsernameExistException("Username já existe");
        }
        return usuarioRepository.save(new UserGrimorium(ud.username(), passwordEncoder.encode(ud.password()))).toDTO();
    }

    @Transactional(readOnly = true)
    public UserGrimorium findByUsername(String username) {
        return usuarioRepository.findByUsername(username);
    }

    @Transactional(readOnly = true)
    public UserGrimorium.Role findRoleByUsername(String username) {
        return usuarioRepository.findRoleByUsername(username);
    }

    @Transactional(readOnly = true)
    public UserResponseDTO getById(Long id) throws NotFoundException {
        return usuarioRepository.findById(id).orElseThrow(() -> new NotFoundException("Usuario não existe")).toDTO();
    }

    public UserResponseDTO updatePassword(Long id, PasswordChangeDTO passwordChangeDTO) throws NotFoundException {
        UserGrimorium usuario = usuarioRepository.findById(id).orElseThrow(() -> new NotFoundException("Usuario não existe"));

        if (passwordChangeDTO.confirmPassword().equals(passwordChangeDTO.password())) {
            if (passwordEncoder.matches(passwordChangeDTO.password(), usuario.getPassword())) {
                usuario.setPassword(passwordEncoder.encode(passwordChangeDTO.password()));
                return usuarioRepository.save(usuario).toDTO();
            } else {
                throw new RuntimeException(String.format("A senha para %s está incorreta", usuario.getUsername()));
            }
        } else {
            throw new RuntimeException("As senha não coincidem");
        }
    }

    public UserGrimorium accountActive(String username) throws Exception {
        UserGrimorium userGrimorium = usuarioRepository.findByUsername(username);
        if (userGrimorium != null) {
            userGrimorium.setSoftDeleted(false);
            return userGrimorium;
        } else {
            throw new Exception("Usuario não encontrado");
        }
    }

    public void deleteAccount(String token) throws NotFoundException {
        UserGrimorium usuario = usuarioRepository.findByUsername(JwtService.getUsernameFromToken(token));
        if (usuario == null) {
            throw new RuntimeException(String.format("Usuario %s não encontrado", usuario.getUsername()));
        } else {
            usuario.setSoftDeleted(true);
            usuarioRepository.save(usuario);
        }
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return findByUsername(username);
    }

    public List<UserResponseDTO> findAll() {
        return usuarioRepository.findAll().stream().map(UserGrimorium::toDTO).collect(Collectors.toList());
    }
}
