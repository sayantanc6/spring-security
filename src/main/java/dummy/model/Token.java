package dummy.model;

import java.io.Serializable;

import org.springframework.data.annotation.Id;
import org.springframework.data.redis.core.RedisHash;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.RequiredArgsConstructor;

@RedisHash("token")
@Data
@AllArgsConstructor
@RequiredArgsConstructor
public class Token implements Serializable {

	private static final long serialVersionUID = 1L;
	
	@Id
	private String username;
	private String token;

}
