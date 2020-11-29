package dummy.repo;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import dummy.entity.Privilege;

@Repository
public interface PrivilegeRepository extends JpaRepository<Privilege, Long> {

	Privilege findByName(String name);

    @Override
    void delete(Privilege privilege);
}
