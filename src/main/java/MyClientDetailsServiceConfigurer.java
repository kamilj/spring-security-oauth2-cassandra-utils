package coop.digi.sdis.services.security.util;

import com.datastax.driver.core.Session;
import org.springframework.security.oauth2.config.annotation.builders.ClientDetailsServiceBuilder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;

public class MyClientDetailsServiceConfigurer extends ClientDetailsServiceConfigurer {

    public MyClientDetailsServiceConfigurer(ClientDetailsServiceBuilder<?> builder) {
        super(builder);
    }

    @Override
    public void configure(ClientDetailsServiceBuilder<?> builder) throws Exception {
        setBuilder(builder);
    }
}
