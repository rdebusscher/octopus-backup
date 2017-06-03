package be.c4j.ee.security;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import javax.interceptor.InvocationContext;
import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

/**
 * Describe in this block the functionality of the class.
 * Created by rubus on 02/06/2017.
 */
@RunWith(MockitoJUnitRunner.class)
public class InvocationContextWrapperTest {

    private InvocationContextWrapper invocationContextWrapper;

    @Mock
    private InvocationContext invocationContextMock;

    @Test
    public void getContextData() {
        Map<String, Object> contextData = new HashMap<String, Object>();
        contextData.put("key1", "Value1");
        contextData.put("key2", "Value2");
        contextData.put("key3", "Value3");

        InvocationContextWrapper wrapper = new InvocationContextWrapper(invocationContextMock, contextData);

        Map<String, Object> originalMap = new HashMap<String, Object>();
        originalMap.put("key2", "OriginalValue2");
        originalMap.put("key4", "Value4");

        when(invocationContextMock.getContextData()).thenReturn(originalMap);

        Map<String, Object> data = wrapper.getContextData();
        assertThat(data).containsKeys("key1", "key2", "key3", "key4");
        assertThat(data).containsEntry("key2", "OriginalValue2");
    }

}