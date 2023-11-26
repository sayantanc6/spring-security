package dummy.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.google.gson.Gson;

import dummy.entity.Product;
import dummy.model.ProductModel;
import dummy.repository.ProductRepository;

@RestController
@RequestMapping("/admin")
@PreAuthorize("hasRole('ROLE_ADMIN')") 
public class AdminController {
	
	@Autowired
	ProductRepository prodrepo;
	 
	@Autowired
	Gson gson;
	
	@PreAuthorize("hasAuthority('admin:create')") 
	@PostMapping(value = "/addproduct",produces = MediaType.APPLICATION_JSON_VALUE,
			headers = "Accept=application/json",consumes = MediaType.APPLICATION_JSON_VALUE)
	public void addproduct(@RequestBody ProductModel product) {
		prodrepo.save(gson.fromJson(gson.toJson(product), Product.class)); 
	}
	
	@PreAuthorize("hasAuthority('admin:delete')") 
	@DeleteMapping(value = "/deleteproduct",produces = MediaType.APPLICATION_JSON_VALUE,
			headers = "Accept=application/json",consumes = MediaType.APPLICATION_JSON_VALUE)
	public void deleteproductbyid(@RequestParam("productid")int productid) {
		prodrepo.deleteById(productid);
	}
}
