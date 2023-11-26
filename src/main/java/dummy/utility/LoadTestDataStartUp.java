package dummy.utility;

import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.ApplicationListener;
import org.springframework.stereotype.Service;

import dummy.entity.Product;
import dummy.repository.ProductRepository;

@Service
public class LoadTestDataStartUp implements ApplicationListener<ApplicationReadyEvent> {

	@Autowired
	ProductRepository prodrepo;

	@Override
	public void onApplicationEvent(ApplicationReadyEvent event) {
		prodrepo.truncateTable();
		
		List<Product> products = IntStream.range(0, 100).boxed()
						.map(i -> Product.builder().name("product"+i).price(Math.random()).quantity(i).build())
						.collect(Collectors.toList());
		 
		prodrepo.saveAll(products);
	}
}
