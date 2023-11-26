package dummy.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import dummy.entity.Product;
import dummy.repository.ProductRepository;

@RestController
@RequestMapping("/user")
@PreAuthorize("hasAnyRole('ROLE_USER','ROLE_ADMIN')")
public class UserController {
	
	@Autowired
	ProductRepository prodrepo; 
	
	@PreAuthorize("hasAnyAuthority('admin:read','user:read')")
	@GetMapping(value = "/findproduct")
	public Product findproductbyid(@RequestParam("productid")int productid) {
		Product product = prodrepo.findById(productid).get(); 
		System.out.println("retrieved product id : "+product); 
		return product;
	}

	@PreAuthorize("hasAnyAuthority('admin:update','user:update')")
	@PutMapping(value = "/updateproduct",produces = MediaType.APPLICATION_JSON_VALUE,
			headers = "Accept=application/json",consumes = MediaType.APPLICATION_JSON_VALUE)
	public void updateproduct(@RequestParam("productid")int productid,@RequestParam("productname")String productname) {
		Product product = prodrepo.findById(productid).get();
		product.setName(productname);
		prodrepo.save(product);
	}
}
