package dummy.config;

import java.lang.reflect.Field;

import com.google.gson.ExclusionStrategy;
import com.google.gson.FieldAttributes;

public class ExcludeNullStrategy implements ExclusionStrategy {
	
	Object fieldname;
	Boolean shouldskip=false;

	@Override
	public boolean shouldSkipField(FieldAttributes f) {
		fieldname = f.getName();
		Field[] fields = f.getClass().getDeclaredFields();
		for (Field field : fields) {
			try {
				if (field.getName().equals(fieldname) && field.get(fieldname)==null) {
					shouldskip = true;
				}
			} catch (IllegalArgumentException | IllegalAccessException e) {
				e.printStackTrace();
			}
		}
		return shouldskip;
	}

	@Override
	public boolean shouldSkipClass(Class<?> clazz) {
		return false;
	}

}
