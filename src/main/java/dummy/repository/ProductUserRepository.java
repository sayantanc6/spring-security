package dummy.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import dummy.entity.ProductUser;

@Repository
public interface ProductUserRepository extends JpaRepository<ProductUser, Integer> {

	Optional<ProductUser> findByUsername(String username);
	
	Boolean existsByUsername(String username);

}
