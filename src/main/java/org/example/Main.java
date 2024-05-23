package org.example;
import com.fazecast.jSerialComm.SerialPort;

import java.io.UnsupportedEncodingException;
import java.util.Arrays;
import java.util.concurrent.*;

import java.util.ArrayList;
import java.util.List;

public class Main {
    public static void main(String[] args) {

        List<Callable<SerialPort>> callables = new ArrayList<>();
        SerialPort[] ports = SerialPort.getCommPorts();
        for(SerialPort p: ports) {
            callables.add(new CallableDetector(p));
        }
        // Create an ExecutorService
        ExecutorService executorService = Executors.newFixedThreadPool(ports.length);

        try {

            SerialPort r = executorService.invokeAny(callables);
            System.out.println("First non-null result: " + r);
        } catch (Exception e) {
            System.out.println(e);
        } finally {
            // Shutdown the executor service
            executorService.shutdown();
        }
    }


}