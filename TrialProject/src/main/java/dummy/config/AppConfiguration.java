package dummy.config;

import org.dozer.DozerBeanMapper;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;

@Configuration
@Import({SpringSecurityConfig.class,MethodSecurityConfig.class})
public class AppConfiguration {

	@Bean
	public DozerBeanMapper  mapper() {
		return new DozerBeanMapper();
	}
}
