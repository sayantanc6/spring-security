package dummy.repository;

import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

import dummy.entity.Product;
import jakarta.transaction.Transactional;

@Repository
@Transactional
public interface ProductRepository extends CrudRepository<Product, Integer> {

	@Modifying
	@Query(value = "truncate table security.Product", nativeQuery = true)
    void truncateTable();
}
