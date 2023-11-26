package dummy.model;

import org.springframework.stereotype.Component;

import com.google.gson.annotations.SerializedName;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Component
@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class ProductModel {

	@SerializedName("name")
	private String name;
	
	@SerializedName("price")
	private double price;
	
	@SerializedName("quantity")
	private int quantity;
}
