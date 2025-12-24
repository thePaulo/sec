package mycompany.ltda.sec;

import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest
class SecApplicationTests {

	@Test
	void contextLoads() {
	}

	@Autowired(required = false)
	private Flyway flyway;

	@Test
	void flywayBeanShouldExist() {
		System.out.println("Flyway bean: " + flyway);
		if (flyway != null) {
			System.out.println("Flyway info: " + flyway.info());
		}
	}

}
