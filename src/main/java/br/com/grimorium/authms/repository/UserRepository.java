package br.com.grimorium.authms.repository;

import br.com.grimorium.authms.model.UserGrimorium;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface UserRepository extends JpaRepository<UserGrimorium, Long> {
    UserGrimorium findByUsername(String username);

    UserGrimorium.Role findRoleByUsername(String username);
}
