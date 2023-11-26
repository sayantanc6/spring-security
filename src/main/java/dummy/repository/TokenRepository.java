package dummy.repository;

import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

import dummy.model.Token;

@Repository
public interface TokenRepository extends CrudRepository<Token, String> {

}
